// Package state implements the authenticated state store for the DPKI system.
//
// The store maps domain names to their DomainState (current certificate, nonce,
// revocation status) and commits the whole mapping to a single 32-byte root hash
// using a Sparse Merkle Tree (SMT). The root hash is what consensus agrees on;
// given the root, any party can be handed a compact cryptographic proof that a
// domain maps to a specific state (inclusion) or that a domain is absent
// (non-inclusion), without trusting the party that produced the proof.
//
// Layering:
//
//   - KVStore        — minimal key/value backend abstraction (kvstore.go).
//   - MemoryStore    — in-memory KVStore for tests and prototyping (memstore.go).
//   - SMT            — generic Sparse Merkle Tree over 32-byte keys (smt.go).
//   - Proof          — compressed inclusion/non-inclusion proofs (proof.go).
//   - Domain helpers — DomainState (de)serialization on top of the SMT (domain.go).
//
// Determinism is the overriding rule: the same operations applied in the same
// order on two independent instances MUST yield a byte-identical root hash.
package state
