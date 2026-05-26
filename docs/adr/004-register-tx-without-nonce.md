# ADR 004: RegisterTx carries no nonce

## Status
Accepted

## Context
Revoke and Rotate transactions use a per-domain nonce to prevent replay attacks
(ADR 001). The question is whether RegisterTx needs the same protection.

A replay of a RegisterTx would attempt to register a domain that already exists
in state. Two scenarios:
1. **Domain is still active** — the application rejects the transaction because
   the domain is already registered; the nonce would add nothing.
2. **Domain was deleted** — if re-registration is ever allowed, a replayed
   RegisterTx from a previous owner could hijack the domain. This risk exists
   regardless of nonce if the new registrant happens to use nonce = 1.

## Decision
`RegisterTx` does not include a nonce field. Replay protection is provided
entirely by the uniqueness invariant enforced by the application state: a
RegisterTx is only accepted if the domain is absent from state. The
`Certificate.ValidFrom` timestamp provides a weak ordering signal but is not
used as a replay counter.

## Consequences
- **Positive:** simpler transaction structure; one less field to validate and
  store.
- **Positive:** consistent with the semantics — nonce tracks mutation count,
  and a domain being registered for the first time has no prior mutations.
- **Negative:** if domain deletion is added in the future, the application must
  ensure that re-registration cannot be replayed from an old signed RegisterTx;
  this may require a tombstone mechanism or a registration-epoch counter.
