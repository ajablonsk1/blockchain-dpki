# ADR 012: Keep default PrepareProposal / ProcessProposal

## Status
Accepted

## Context
ABCI 2.0 adds two proposer-time hooks: `PrepareProposal` (the proposer selects
and may reorder/modify the transactions for its block) and `ProcessProposal`
(every validator validates a proposed block before voting). They are the place
to implement block-level policy: gas metering, per-sender rate limiting,
anti-spam, transaction ordering rules.

`abci.BaseApplication` provides defaults: `PrepareProposal` takes the mempool
transactions in order up to the size limit, and `ProcessProposal` accepts every
proposed block.

## Decision
The application embeds `abci.BaseApplication` and does **not** override
`PrepareProposal` or `ProcessProposal`. The MVP relies on per-transaction
validation in `CheckTx` and `FinalizeBlock` (ADR 011) for all correctness;
block-level policy is out of scope for a single-node prototype.

## Consequences
- **Positive:** less code and no second place where transaction validity is
  judged; a transaction's fate is decided entirely by `CheckTx`/`FinalizeBlock`.
- **Positive:** `ProcessProposal` accepting all blocks is safe here because every
  transaction is fully re-validated in `FinalizeBlock`, so an invalid one is
  recorded with a non-zero code rather than corrupting state.
- **Negative:** there is no gas, no rate limit, and no anti-spam ordering. A
  single node is not adversarial, but a public multi-node deployment would need
  `PrepareProposal`/`ProcessProposal` to bound block work and reject spam before
  execution. Recorded as future work and discussed in the security analysis.
