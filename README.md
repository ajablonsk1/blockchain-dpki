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
│   └── dpki-cli/       # CLI client entrypoint
├── internal/
│   ├── app/            # application logic
│   ├── crypto/         # cryptographic primitives
│   ├── state/          # blockchain state management
│   └── types/          # shared domain types
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
