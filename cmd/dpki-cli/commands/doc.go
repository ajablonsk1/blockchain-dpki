// Package commands defines the Cobra command tree of dpki-cli.
//
// Commands hold no business logic (ADR 017): they read flags, build and sign
// transactions with internal/types and internal/crypto, talk to the node through
// the client package, and format results. Every validation decision is the
// node's; the only cryptographic work done locally is signing and Merkle-proof
// verification.
package commands
