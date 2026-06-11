# ADR 018: Node access through the official CometBFT JSON-RPC client

## Status
Accepted

## Context
The CLI needs four node calls: `status`, `broadcast_tx_commit`, `abci_query`
and `header`. Candidate transports:

1. **Hand-rolled HTTP + JSON parsing** — full control, but CometBFT's JSON-RPC
   encodes `[]byte` as base64, `int64` as strings and proofs inside a nested
   envelope; getting every decode right (and keeping it right across CometBFT
   upgrades) is exactly the class of silent bug a PKI client cannot afford.
2. **gRPC** — CometBFT v0.38 exposes only a minimal broadcast service over
   gRPC; queries and headers would still need JSON-RPC.
3. **Official Go client** `github.com/cometbft/cometbft/rpc/client/http` —
   same JSON-RPC over HTTP wire protocol, with all encoding/decoding owned by
   the CometBFT module the node itself is built from.

## Decision
Use the official client, wrapped in `cmd/dpki-cli/client`:

- The wrapper exposes DPKI-shaped calls (`QueryDomain`, `QueryDomainProof`,
  `AppHashAt`, `BroadcastTxCommit` taking a `*types.Transaction`) and rewraps
  transport errors with the node address and an actionable hint.
- Transactions are serialized with `proto.MarshalOptions{Deterministic: true}`,
  the exact wire format the app decodes (ADR 002).
- The `dpki:smt` proof travels inside `ResponseQuery.ProofOps` and is decoded
  with `state.Proof.UnmarshalBinary` (ADR 010); the generic CometBFT proof
  runtime is not involved.
- The RPC timeout is 15s — above the 10s CometBFT may hold a
  `broadcast_tx_commit` while waiting for the block.

## Consequences
- **Positive:** no fragile manual base64/string-int decoding; response types
  are the same structs the node serializes.
- **Positive:** version skew between client and node is caught by the shared
  go.mod pin of CometBFT.
- **Negative:** the client binary links CometBFT's RPC stack; size and
  dependency surface grow. Accepted — the module already depends on CometBFT.
- **Negative:** JSON-RPC over HTTP only; no streaming subscriptions. Not
  needed by any Phase 5 command.
