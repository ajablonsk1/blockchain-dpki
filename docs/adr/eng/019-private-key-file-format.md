# ADR 019: Private key storage format

## Status
Accepted

## Context
`dpki-cli` keeps user keys on disk. Candidate formats: PEM/PKCS#8 (standard
but pulls in ASN.1 and invites algorithm ambiguity), an encrypted JSON
keystore (best protection, but needs passphrase UX, KDF choices and recovery
flows), or raw key bytes.

## Decision
A key file holds the **raw 64-byte Ed25519 private key** (seed ‖ public key,
the `crypto/ed25519` native layout) and nothing else.

Handling rules, enforced in `internal/crypto` and the `keys` commands:

- Files are written with mode **0600**; `keys generate` refuses to overwrite
  an existing file and creates parent directories 0700.
- Reading **rejects** keys with group/world permission bits
  (`ErrInsecurePermissions`) instead of warning and proceeding.
- The private key is never printed or logged — `keys show` prints only the
  public key, its SHA-256 fingerprint and the algorithm; verbose mode logs
  sign bytes and signatures, never the key.

## Consequences
- **Positive:** zero parsing ambiguity; the file *is* the key, trivially
  auditable and testable.
- **Positive:** insecure-permission rejection turns a silent misconfiguration
  into a hard, actionable error.
- **Negative:** no encryption at rest; whoever reads the file owns the domain.
  Accepted for the thesis MVP and listed as future work (passphrase-encrypted
  keystore), mitigated by 0600 + the permission check.
- **Negative:** one file per key, no keyring; key inventory is the user's
  filesystem hygiene.
