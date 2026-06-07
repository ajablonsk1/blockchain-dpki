# ADR 005: chain_id included in SignBytes

## Status
Accepted

## Context
A signed transaction is a sequence of bytes tied to a specific intent. Without
a chain identifier, a transaction signed for a test network could be replayed
on the production network (or any other deployment sharing the same genesis).
This is the cross-chain replay attack.

Options considered:
- **Omit chain_id from signing** — simplest, but enables cross-chain replay.
- **Include chain_id as a separate prefix before signing** — explicit but
  requires a custom pre-processing step outside the protobuf schema.
- **Include chain_id as a field in the Transaction message and cover it with
  the signature** — chain_id is already a first-class field in `Transaction`;
  since `SignBytes` serializes all fields except `Signature`, chain_id is
  automatically included in the signed payload.

## Decision
`chain_id` is a required field of `Transaction` (rejected by `Validate` if
empty or longer than `MaxChainIDLength = 50`). Because `SignBytes` marshals
the full transaction minus the `Signature` field, `chain_id` is always part of
the signed payload. No extra handling is needed.

## Consequences
- **Positive:** cross-chain replay is prevented without any special-casing in
  the signing logic.
- **Positive:** chain_id is visible in the transaction record, making auditing
  straightforward.
- **Negative:** every transaction must carry a chain_id; clients that forget to
  set it will have their transactions rejected at `Validate`, which is the
  desired behaviour but may surprise developers unfamiliar with the requirement.
