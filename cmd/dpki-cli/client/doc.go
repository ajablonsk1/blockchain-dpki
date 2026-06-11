// Package client wraps the CometBFT JSON-RPC client with DPKI-specific calls:
// broadcasting signed transactions, querying domain state with or without a
// Merkle proof, and resolving the app hash a proof verifies against.
//
// The package contains no business logic — every validation decision is made by
// the node; the client only encodes requests and decodes responses (ADR 018).
package client
