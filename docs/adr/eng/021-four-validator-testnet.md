# ADR 021: Four validators in the reference testnet

## Status
Accepted

## Context
The testnet must demonstrate the properties the thesis claims: decentralized
operation, state replication, deterministic execution and BFT fault tolerance.
CometBFT consensus tolerates `f` Byzantine validators only when the total is
`n ≥ 3f + 1`; block finality requires more than 2/3 of voting power. Common
testnet sizes are 4, 7, 10 or 21 validators; each extra node adds a process,
logs and startup time without changing the math.

## Decision
**Four validators with equal voting power** — the smallest `n` with non-trivial
fault tolerance (`f = 1` from `n = 3f + 1`). This size demonstrates every
regime the security analysis needs:

- 4/4 alive — normal consensus, ~1s blocks;
- 3/4 alive (75% > 2/3) — consensus and writes continue: the tolerated single
  failure;
- 2/4 alive (50% < 2/3) — consensus **halts** rather than forks: CometBFT
  chooses safety over liveness, the empirical argument that a DPKI built on
  BFT cannot be split-brained into serving two certificate histories;
- recovery — restarted validators rejoin and all app hashes reconverge.

The topology is a full mesh via `persistent_peers`; all validators are equal
(no seeds, no sentries) — sufficient on one machine and the simplest honest
configuration.

## Consequences
- **Positive:** every BFT regime (work, tolerate, halt, recover) is shown with
  the fewest moving parts; scenarios run in minutes on a laptop.
- **Positive:** `n = 4` keeps logs small enough to quote in the thesis.
- **Negative:** one machine means no real network latency or partitions; the
  performance numbers of Phase 7 must be read as lower bounds on latency.
- **Negative:** `f = 1` cannot demonstrate sub-quorum Byzantine *behavior*
  (e.g. equivocation by a minority); that analysis stays theoretical.
