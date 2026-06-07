# ADR 011: Light validation in CheckTx, authoritative validation in FinalizeBlock

## Status
Accepted

## Context
A transaction is validated in two very different contexts. `CheckTx` gates the
mempool: it runs often, on transactions that may never be included, and must be
cheap and must not mutate state. `FinalizeBlock` executes the agreed block: it
runs once per included transaction and is the only place where acceptance is
authoritative and state actually changes.

The risk is doing too much in `CheckTx` (e.g. enforcing the exact next nonce)
and dropping transactions from the mempool that are perfectly valid once their
predecessor lands, or doing too little and admitting obvious garbage that wastes
block space.

## Decision
Both paths share the first three stages — decode, syntactic `Validate()`, chain
ID match, signature verification against the owning key — but differ on
semantics:

- **CheckTx (light):** the domain exists when it must, is not revoked, and the
  nonce is *not stale* (`nonce > stored`). It deliberately does **not** require
  the exact next nonce, so a transaction queued ahead of its predecessor is not
  rejected.
- **FinalizeBlock (authoritative):** the full semantic check, including the
  **exact** next nonce (`nonce == stored + 1`), and then the state mutation.

`CheckTx` never writes state; it only reads. The exact-nonce and
already-registered/already-revoked decisions that determine the canonical
outcome live solely in `FinalizeBlock`.

## Consequences
- **Positive:** cheap, side-effect-free mempool admission that still rejects
  bad signatures and clearly-doomed transactions before they reach a block.
- **Positive:** correctness does not depend on `CheckTx`; even if a node skipped
  it, `FinalizeBlock` would still enforce every rule.
- **Negative:** validation logic is expressed twice (a light and a full variant),
  which must be kept in sync. The shared decode/validate/signature helper limits
  the duplication to the semantic layer.
- **Negative:** the lenient nonce rule in `CheckTx` lets a future-nonce
  transaction sit in the mempool and ultimately fail in `FinalizeBlock`; this is
  preferable to dropping reorderable-but-valid transactions, and anti-spam is
  deferred to a later gas/limit mechanism (ADR 012).
