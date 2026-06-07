# ADR 010: Query paths and proof transport

## Status
Accepted

## Context
Clients read state through ABCI `Query`. Two needs exist: a plain lookup of a
domain's current state, and a lookup accompanied by a cryptographic proof that a
light client can verify offline against the committed app hash — the feature
that replaces CRL/OCSP with a self-verifying answer (ADR 007).

The proof produced by the state package is a compact Go struct (`state.Proof`:
key, value, sibling hashes, bitmap). It must travel over the wire in a stable
encoding, and it must fit the `ResponseQuery` shape CometBFT already defines.

## Decision
Two query paths:

- `/domain` — `req.Data` is the domain name; `Value` is the marshaled
  `DomainState`, or empty for an unregistered domain. Absence is not an error
  (`Code == 0`).
- `/domain/proof` — same `Value`, plus a proof in `ResponseQuery.ProofOps`. The
  proof travels as a single `ProofOp{Type: "dpki:smt", Key: domainKey, Data:
  proofBytes}`, where `proofBytes` is `state.Proof.MarshalBinary()`. The client
  decodes it with `UnmarshalBinary` and verifies it with
  `state.VerifyDomainProof` against a trusted root.

`state.Proof` gets an explicit, self-describing binary codec
(`MarshalBinary`/`UnmarshalBinary`) rather than reusing protobuf or Go's `gob`,
so the wire format is stable and independent of in-memory layout.

## Consequences
- **Positive:** proofs are transported within the standard `ResponseQuery`
  envelope; no side channel.
- **Positive:** inclusion and non-inclusion are handled uniformly — both return a
  verifiable proof; only `Value` distinguishes them.
- **Negative:** the `ProofOp.Type` string `"dpki:smt"` is a private convention,
  not a registered CometBFT proof operator, so the generic CometBFT proof-runtime
  cannot verify it; verification goes through `state.VerifyDomainProof`. That is
  acceptable because the light client is ours and links the state package.
- **Negative:** a second, app-specific binary format exists alongside protobuf;
  it is small and fully covered by round-trip and truncation tests.
