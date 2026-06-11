# ADR 022: Testnet tooling — Go subcommand, local processes first, Docker as demo

## Status
Accepted

## Context
Initializing a multi-validator testnet is fiddly: every home needs unique
validator and node keys, a byte-identical genesis listing all validators,
non-clashing ports and correctly formatted `persistent_peers`
(`node_id@host:port`). A bash script doing this would shell out to the
`cometbft` binary (a dependency we do not otherwise ship) and rewrite TOML
with `sed`. There is also a topology question: local processes or containers?

## Decision
Three pieces, each with one job:

1. **`dpkid testnet init`** (Go) generates the homes. It reuses the same
   CometBFT config/privval/p2p libraries the node itself runs, so there is no
   external binary and no text munging: ports are set on the `Config` struct,
   peers are computed from real `NodeKey` IDs, and one `GenesisDoc` is saved
   into every home. `--docker` switches peer addressing from
   `127.0.0.1:26656+10i` to the compose hostnames `node{i}:26656`.
   Localhost full-mesh requires `AllowDuplicateIP = true` and
   `AddrBookStrict = false`.
2. **Local processes** (`scripts/start-testnet.sh` / `stop-testnet.sh`) are
   the primary development topology: instant startup, logs as plain files,
   nodes killable individually — which the fault-tolerance tests rely on.
3. **Docker Compose** is the demo/reproducibility topology: one
   `docker compose up --build` gives a reviewer the full testnet with the
   same host-visible RPC ports, so every `dpki-cli` example works unchanged.

## Consequences
- **Positive:** testnet generation is typed, tested Go code; the genesis and
  peer-format pitfalls are eliminated by construction.
- **Positive:** the fault-tolerance harness (`scripts/test-testnet.sh`) can
  kill and restart individual validators trivially.
- **Negative:** two topologies to keep working (process and container); the
  container path shares the init code, so the surface is small.
- **Negative:** `testnet init` only generates static local/compose setups —
  no cloud provisioning; out of scope for the thesis.
