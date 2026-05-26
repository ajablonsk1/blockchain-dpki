# ADR 002: Protobuf with deterministic marshalling over JSON canonical serialization

## Status
Accepted

## Context
Transaction signing requires a byte representation that is:
1. **Deterministic** — same logical message always produces the same bytes.
2. **Complete** — all fields that affect validity are included.
3. **Cross-language** — other nodes or clients may be written in languages
   other than Go.

Candidates considered:
- **JSON canonical (RFC 8785 / JCS)** — human-readable, widely understood, but
  requires an extra canonicalization library and is slower to parse.
- **protobuf with `MarshalOptions{Deterministic: true}`** — already used for
  transport; deterministic mode sorts map keys and produces stable output
  within a single binary version.
- **Raw field concatenation** — fast but fragile; adding a field silently
  breaks the signing scheme.

## Decision
Use `proto.MarshalOptions{Deterministic: true}` to produce the canonical byte
representation for both signing (`SignBytes`) and hashing (`Hash`). The
`Signature` field is zeroed before marshalling so it is excluded from the
signed payload (see `Transaction.SignBytes`).

## Consequences
- **Positive:** no additional dependencies; protobuf is already the wire format.
- **Positive:** schema evolution (adding optional fields) is safe as long as
  old signers set new fields to their zero values.
- **Negative:** protobuf's deterministic mode is guaranteed only within the
  same protobuf library version. A major library upgrade must be tested for
  serialization stability before deployment.
- **Negative:** signed bytes are not human-readable; debugging requires a
  proto-aware tool.
