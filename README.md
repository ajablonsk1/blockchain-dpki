# DPKI — Decentralized Public Key Infrastructure

A blockchain-based Decentralized Public Key Infrastructure (DPKI) using BFT consensus via CometBFT. Built as a master's thesis project.

## Requirements

- Go 1.25+
- `golangci-lint` — for `make lint`
- `gofumpt` + `goimports` — for `make fmt`

## Quick Start

```bash
make build        # compile both binaries into ./bin/
make run-dpkid    # build and run the blockchain node
make run-client   # build and run the CLI client
```

For the full client workflow (keys, DNS-01 challenge, register, lookup with
Merkle proofs, offline verification) see [`cmd/dpki-cli/README.md`](cmd/dpki-cli/README.md).
End-to-end test against a real node: `./scripts/test-e2e.sh`.

### Multi-validator testnet

```bash
./bin/dpkid testnet init                 # 4 validator homes, shared genesis
./scripts/start-testnet.sh --no-verify   # local processes
# or: ./bin/dpkid testnet init --docker --output-dir ./testnet-docker && docker compose up --build
./scripts/test-testnet.sh                # replication, determinism, BFT fault tolerance
```

See [`docs/testnet/README.md`](docs/testnet/README.md) for topology and the
fault-tolerance scenarios.

### Evaluation (security + performance)

```bash
./scripts/run-benchmarks.sh                       # full campaign -> results/<timestamp>/
python3 scripts/plot-results.py results/<ts>      # charts (PNG+SVG) for the thesis
go test -run 'TestSTRIDE|TestFrontRunning' ./internal/app -v   # security suite alone
```

Threat model and STRIDE mapping: [`docs/security/adversary-model.md`](docs/security/adversary-model.md).

## Make Targets

| Target | Description |
|---|---|
| `build` | Compile `dpkid` and `dpki-cli` into `./bin/` |
| `run-dpkid` | Build and run the blockchain node |
| `run-client` | Build and run the CLI client |
| `test` | Run all tests with race detector |
| `test-cover` | Run tests with coverage, output `coverage.html` |
| `lint` | Run `golangci-lint` |
| `fmt` | Format code with `gofumpt` and `goimports` |
| `clean` | Remove `./bin/`, `coverage.out`, `coverage.html` |

## Project Structure

```
.
├── cmd/
│   ├── dpkid/          # blockchain node entrypoint
│   └── dpki-cli/       # CLI client (commands/ + RPC client/)
├── internal/
│   ├── app/            # application logic
│   ├── crypto/         # cryptographic primitives
│   ├── state/          # blockchain state management
│   ├── types/          # shared domain types
│   └── verifier/       # DNS-01 domain ownership verification
├── pkg/
│   └── merkle/         # reusable Merkle tree library
├── playground/         # prototypes and experiments
│   ├── comet-bft/      # CometBFT integration experiments
│   ├── crypto/         # cryptographic algorithm experiments
│   ├── integration/    # end-to-end prototype scenarios
│   ├── merkle-trees/   # Merkle tree experiments
│   └── pki/            # PKI case studies (CT, DigiNotar)
├── docs/
│   └── masters-thesis/ # LaTeX thesis source
└── scripts/            # utility scripts
```
