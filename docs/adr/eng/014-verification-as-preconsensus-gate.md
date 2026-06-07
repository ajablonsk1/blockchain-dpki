# ADR 014: Domain verification is a pre-consensus gate, not part of FinalizeBlock

## Status
Accepted

## Context
Domain verification (ADR 013) is a DNS lookup: non-deterministic external I/O.
The blockchain state machine, by contrast, must be perfectly deterministic —
every validator must compute the same app hash, and a node restarting must
recompute the same history.

Putting the DNS lookup inside `FinalizeBlock` breaks both:

- **Replay:** with the in-memory backend, a restarting node rebuilds state by
  re-running `FinalizeBlock` over its block history (ADR 009). By then the owner
  has removed the challenge TXT record (it is only needed once), so the same
  `RegisterTx` would now fail verification — the recomputed app hash would
  diverge from the committed history and the node could never catch up.
- **Multi-node:** different validators querying DNS at different moments (caches,
  TTLs, propagation) can see different results, producing different app hashes
  for the same block and splitting consensus.

The original phase plan proposed verifying in `FinalizeBlock` with a grace
period; that does not solve either problem, because re-execution happens
arbitrarily later than any grace period.

## Decision
Verification runs **only before consensus**, never in `FinalizeBlock`:

- **CheckTx** verifies a `RegisterTx` before admitting it to the mempool (the DNS
  lookup runs outside the state lock so network I/O never blocks block
  execution).
- **ProcessProposal** re-verifies every registration in a proposed block; if any
  fails, the validator rejects the whole block. This stops a proposer from
  smuggling an unverified registration past the mempool.
- **FinalizeBlock** does no verification at all: it deterministically applies
  whatever consensus agreed to include. A registration that reached a finalized
  block *is* the record that verification passed.

## Consequences
- **Positive:** `FinalizeBlock` stays deterministic and replay-safe; the app hash
  depends only on the committed transactions, not on live DNS.
- **Positive:** verification still gates every honest path — mempool admission and
  block proposal — so an unverified registration cannot be committed by a correct
  validator set.
- **Negative:** this is a deliberate deviation from the phase plan, which placed
  verification in `FinalizeBlock`. The trade-off is that verification is a
  liveness/admission property, not a property re-checked at execution time.
- **Negative:** `ProcessProposal` doing DNS I/O means a transient DNS outage can
  make a validator reject an otherwise-valid block, affecting liveness. Bounded
  retries/backoff are noted as future work; for a single-node MVP it is moot.
- **Negative:** in a Byzantine multi-node setting, a colluding proposer plus
  validators could still admit an unverified registration; full protection needs
  every honest validator to verify, which `ProcessProposal` provides as long as
  the honest majority can resolve DNS.
