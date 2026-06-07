# ADR 015: Deterministic, key-bound challenge value

## Status
Accepted

## Context
The challenge value published in DNS must be reproducible by both the client
(when instructing the owner) and every validator (when checking), so it cannot
contain server-chosen randomness. It must also be bound to the registration in a
way that defeats front-running: an attacker who sees a pending `RegisterTx` must
not be able to reuse the same published record for a registration under their own
key.

## Decision
The challenge is a hash over the public, transaction-bound inputs, with domain
separation:

```
challenge = SHA-256( domain || 0x00 || pubKey || 0x00 || chainID )   (lower-case hex)
```

published at `_dpki-challenge.<domain>` (ADR 013). The `0x00` separators prevent
concatenation collisions (e.g. `("ab","c")` vs `("a","bc")`).

Binding to:
- **pubKey** is the anti-front-running property: the value the real owner
  publishes is tied to *their* key, so an attacker substituting their own key
  computes a different expected value and the published record will not match.
- **chainID** stops a challenge published for one chain being replayed to claim
  the domain on another.

No server-side randomness is used; determinism is required for client/validator
agreement, and the public-key binding already provides per-registration
uniqueness and unguessability (the key is freshly generated).

## Consequences
- **Positive:** client and validators derive the identical value with no shared
  secret or coordination.
- **Positive:** front-running is defeated structurally rather than by timing.
- **Negative:** the value is fully determined by public inputs, so it is *not*
  secret — anyone observing the chain can compute it. This is fine: only the
  domain's real DNS controller can publish it under the domain, and only the
  holder of the private key can sign the matching transaction.
- **Negative:** the format is fixed; changing the preimage or hash is a
  breaking change to verification and must be versioned alongside the state
  encoding.
