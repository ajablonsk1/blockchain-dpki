# ADR 003: Ed25519 as the default signature algorithm

## Status
Accepted

## Context
The system needs a public-key signature scheme for authenticating transactions.
Requirements: small key and signature sizes (keys travel in every certificate
and transaction), fast verification (every node verifies every transaction),
and resistance to implementation pitfalls.

Candidates considered:
- **ECDSA P-256** — widely deployed (TLS, X.509), hardware support, but
  requires a random nonce per signature; a weak or reused nonce leaks the
  private key. Included in the `Algorithm` enum as `ALGORITHM_ECDSA_P256` but
  returns `ErrAlgorithmNotSupported` in `validatePublicKey`.
- **RSA-2048/4096** — well-understood, but large key sizes (256–512 bytes vs.
  32 bytes for Ed25519) and slow verification make it unsuitable for
  high-throughput blockchain use.
- **Ed25519** — deterministic (no per-signature randomness), 32-byte keys,
  64-byte signatures, fast batch verification, and immune to the nonce-reuse
  class of attacks.

## Decision
Ed25519 (`ALGORITHM_ED25519 = 1`) is the only supported algorithm. ECDSA P-256
is reserved in the enum for forward compatibility but is explicitly rejected
at validation time.

## Consequences
- **Positive:** small, fixed-size keys and signatures simplify state layout and
  wire format.
- **Positive:** deterministic signing eliminates an entire class of
  implementation bugs.
- **Negative:** Ed25519 is not yet universally supported in HSMs and
  enterprise PKI tooling; adding ECDSA support in the future requires
  implementing `validatePublicKey` for that variant.
