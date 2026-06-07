# ADR 007: Sparse Merkle Tree for authenticated state commitment

## Status
Accepted

## Context
The system must commit the entire domain → state mapping to a single root hash
that consensus agrees on, and must let any party verify, against that root, both
that a domain maps to a specific state (**inclusion**) and that a domain is
**absent** (**non-inclusion**). Non-inclusion is what lets a relying party prove
"this certificate is *not* the current binding for this domain", and inclusion of
a `revoked` state is what replaces CRL/OCSP with a single, always-available,
self-verifying proof against the committed root.

Tree options considered:

| Option | Pros | Cons |
|---|---|---|
| Plain binary Merkle tree | Easy to implement and describe | Position depends on insertion order; no efficient non-inclusion proofs |
| Sparse Merkle Tree (SMT) | Deterministic by key, native non-inclusion proofs, industry standard | More involved than a plain tree |
| IAVL (Cosmos SDK, off the shelf) | Production-ready | Little is implemented by us; harder to claim as a contribution |

A plain binary tree (as in `playground/merkle-trees`) commits an ordered *list*;
its leaf positions depend on insertion order and it has no natural notion of "key
absent", so it cannot produce non-inclusion proofs. That is disqualifying here.

## Decision
Implement a custom **Sparse Merkle Tree** in `internal/state`:

- **Fixed depth 256.** Keys are SHA-256 digests of domain names (ADR 002/003 use
  SHA-256 throughout). Each key addresses exactly one leaf at depth 256, so a
  leaf's position depends only on its key — never on history. This is what makes
  the root deterministic across insertion order, the overriding requirement.
- **Default hashes.** The hash of an all-empty subtree at each depth is
  precomputed. An absent sibling is, by definition, the default hash for its
  depth, so the tree represents 2^256 possible leaves while storing only
  populated paths. The empty-tree root is the depth-0 default hash.
- **Domain separation.** Leaf preimages are tagged `0x00`, internal-node
  preimages `0x01`. This makes it impossible to reinterpret a leaf hash as an
  internal-node hash (or vice versa), closing a class of second-preimage
  ambiguities at negligible cost.
- **Canonical node set.** On every update the single root-to-leaf path is
  rewritten; nodes whose hash collapses to the default for their depth are
  deleted, not stored. Deleting a key restores the exact root the tree would have
  had if the key had never been inserted, so two backends with identical content
  hold an identical node set.
- **Compressed proofs.** A naive SMT proof carries 256 sibling hashes (8 KiB). We
  carry instead a 256-bit bitmap marking which levels have a non-default sibling,
  plus only those siblings; the verifier reconstructs the rest from their depth.
  In a tree of 10,000 entries a proof is ~14 siblings / ~520 bytes.
- **Standalone verification.** `VerifyProof` and `VerifyDomainProof` need only a
  root and a proof, no tree access, so a light client (e.g. a TLS client) can
  verify a domain's current, non-revoked binding offline.

## Consequences
- **Positive:** native, cheap non-inclusion proofs — the technical core of the
  thesis claim against CRL/OCSP.
- **Positive:** order-independent, byte-identical roots across nodes; this is
  what consensus requires.
- **Positive:** fully implemented in-house → a complete chapter to write and
  defend, citing the SMT lineage (Plasma, Diem/Libra, Ethereum stateless).
- **Negative:** every update rewrites 256 levels (~256 hashes); for the prototype
  this is fine (~0.18 ms/update in benchmarks), but a production system would
  adopt a compact/optimized SMT (e.g. Jellyfish Merkle) to collapse single-child
  paths. Recorded as future work.
- **Negative:** determinism depends on the SHA-256 construction and the fixed
  domain-separation/encoding scheme; any change to them is a breaking change to
  the state root and must be versioned.
