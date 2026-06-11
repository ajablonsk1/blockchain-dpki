# ADR 023: Crash recovery by block replay instead of state persistence

## Status
Accepted

## Context
Application state lives in an in-memory SMT (`state.MemoryStore`, ADR 006);
a restarted validator comes back with an empty tree at height 0. The testnet
must nevertheless demonstrate recovery: a killed validator rejoins and ends up
with the same app hash as the others. The alternative is a persistent KVStore
(e.g. BadgerDB), which needs crash-consistent commits aligned with CometBFT's
Commit, snapshotting and its own ADR-worth of failure modes.

## Decision
**Recovery relies on CometBFT replay; the application persists nothing.**
CometBFT persists the block store and WAL in the node home. On restart the
ABCI handshake compares the app's height (0, in-memory) with the stored chain
and replays every committed block through `FinalizeBlock`, deterministically
rebuilding the SMT; blocksync then fetches the blocks missed while down and
the validator rejoins consensus.

Two earlier decisions make this sound:

- execution is fully deterministic (ADR 002, 009) — replay provably reproduces
  the same app hash, which the recovery test asserts across all validators;
- DNS-01 verification is a pre-consensus gate, never in `FinalizeBlock`
  (ADR 014) — replay does not re-run DNS lookups, so registrations whose TXT
  records are long gone replay cleanly.

## Consequences
- **Positive:** zero persistence code in the application; the SMT stays a pure
  in-memory structure and the replay path doubles as a standing determinism
  test of the whole transaction history.
- **Positive:** "wipe the app, keep the chain" recovery is exactly the
  trust-minimized story: state is always re-derivable from consensus.
- **Negative:** restart cost grows linearly with chain length (replay all
  blocks). Fine for a thesis testnet; a production deployment would add a
  persistent KVStore behind the existing `state.KVStore` interface (ADR 006)
  without touching consensus.
- **Negative:** no state-sync snapshots for fast-joining new nodes; new
  validators replay from genesis too.
