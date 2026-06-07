# ADR 009: Apply state directly in FinalizeBlock (no working copy)

## Status
Accepted

## Context
ABCI splits block execution into `FinalizeBlock` (run the transactions, return
the app hash) and `Commit` (persist). A common pattern is to apply transactions
to a *working copy* of state in `FinalizeBlock` and only promote it to the
canonical state in `Commit`, so a block that is somehow abandoned leaves no
trace.

A working copy needs cheap state snapshots and rollback. The current state
backend is an in-memory `MemoryStore` behind the minimal `KVStore` interface
(ADR 006), which has neither. Implementing copy-on-write or a savepoint
mechanism would be real work for a property the single-node MVP does not need:
CometBFT calls `FinalizeBlock` then `Commit` in sequence for each agreed block,
and a finalized block is never rolled back in normal single-node operation.

## Decision
`FinalizeBlock` applies each transaction directly to the state tree and returns
the resulting Merkle root as the app hash. `Commit` is a no-op that simply
acknowledges the block. A transaction that fails validation returns a non-zero
result code and leaves state untouched, but does not abort the block.

All ABCI entry points serialize access to the tree through a single `RWMutex`:
`FinalizeBlock`/`InitChain` take the write lock, `CheckTx`/`Query`/`Info` take
the read lock, because CometBFT drives the consensus, mempool and query
connections concurrently.

## Consequences
- **Positive:** no snapshot/rollback machinery; the app stays small and the state
  package keeps its minimal interface.
- **Positive:** the app hash is computed exactly where ABCI 2.0 expects it
  (`FinalizeBlock`), not in `Commit` as in ABCI 1.0.
- **Negative:** there is no atomic block boundary inside the app. This is safe
  for one node but must be revisited for a persistent, multi-node deployment,
  where a working copy (or a transactional backend such as BadgerDB with
  savepoints) is needed so a block can be discarded cleanly. Recorded as future
  work.
- **Negative:** with the in-memory backend, a restart loses state; CometBFT
  replays its block history via `FinalizeBlock` to rebuild it, which is why the
  chain ID is taken from genesis at construction rather than from `InitChain`
  (which runs only once).
