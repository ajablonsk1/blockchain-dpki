// Package crypto provides low-level cryptographic primitives for the DPKI
// system: Ed25519 key generation and file I/O, SHA-256 hashing, and
// Ed25519 signing and verification.
//
// All functions operate on raw byte slices rather than typed key structs to
// keep the interface minimal and avoid pulling higher-level types into the
// crypto layer.
package crypto
