// Package app implements the DPKI ABCI 2.0 application that runs on top of
// CometBFT. It translates consensus-ordered transactions into deterministic
// updates of the authenticated state held in internal/state.
//
// Transaction lifecycle:
//
//   - CheckTx       — cheap, read-only mempool admission: syntactic validation,
//     chain-id check, signature verification, and a light semantic check.
//   - FinalizeBlock — full validation plus application: each transaction is
//     decoded, validated, signature-checked, then dispatched to a handler that
//     mutates the tree. The Merkle root is returned as the app hash.
//   - Commit        — acknowledges the block; state is already applied.
//   - Query         — reads committed state, optionally with a Merkle proof that
//     verifies offline against the app hash.
//
// Supported transactions are Register (bind a domain to a new certificate),
// Revoke (mark a binding revoked), and Rotate (replace a domain's key). A
// domain's mutations are ordered by a per-domain nonce: a freshly registered
// domain is at nonce 0, and each Revoke/Rotate must carry the exact next value.
//
// Determinism is mandatory: identical transactions applied in identical order on
// two nodes MUST yield a byte-identical app hash.
package app
