package state

import "bytes"

// Proof is a compressed Merkle proof for a single key against an SMT root. It
// proves either inclusion (Value != nil — the key maps to exactly that value) or
// non-inclusion (Value == nil — the key is absent).
//
// Compression: a full SMT proof is one sibling hash per level (TreeDepth = 256
// of them). In a sparse tree almost all of those siblings are default hashes,
// fully determined by their depth. Bitmap records, bit by bit, which levels have
// a non-default sibling; only those siblings are carried in Siblings. A verifier
// reconstructs the default ones from their depth. Bit i of Bitmap corresponds to
// the proof step starting at tree depth TreeDepth-i (i.e. i = 0 is the leaf's
// sibling, i = 255 is the sibling just below the root).
type Proof struct {
	Key      []byte   // 32-byte SMT key the proof is about
	Value    []byte   // stored value for inclusion; nil for non-inclusion
	Siblings [][]byte // non-default sibling hashes, ordered leaf -> root
	Bitmap   []byte   // 32 bytes (256 bits); set bit i => Siblings carries level i
}

// IsInclusion reports whether the proof asserts the key is present.
func (p *Proof) IsInclusion() bool { return p.Value != nil }

// Prove returns a compressed proof for key against the current root. If key is
// present the proof is an inclusion proof carrying its value; otherwise it is a
// non-inclusion proof. key must be KeySize bytes.
func (s *SMT) Prove(key []byte) (*Proof, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeyLength
	}

	value, present, err := s.Get(key)
	if err != nil {
		return nil, err
	}

	p := &Proof{
		Key:    append([]byte(nil), key...),
		Bitmap: make([]byte, KeySize),
	}
	if present {
		p.Value = value
	}

	for d := TreeDepth; d >= 1; d-- {
		sibHash, err := s.getNode(d, siblingMask(key, d))
		if err != nil {
			return nil, err
		}

		if !bytes.Equal(sibHash, defaultHashes[d]) {
			idx := TreeDepth - d
			setBit(p.Bitmap, idx)
			p.Siblings = append(p.Siblings, sibHash)
		}
	}

	return p, nil
}

// VerifyProof checks p against a 32-byte root with no access to the tree. It
// recomputes the root from the leaf upward, substituting default hashes for the
// levels Bitmap marks as absent, and returns true only if the result matches
// root and every carried sibling was consumed (no trailing/garbage siblings).
//
// A true result for an inclusion proof means: under this root, p.Key maps to
// exactly p.Value. For a non-inclusion proof it means: under this root, p.Key is
// absent. This is the verification a light client performs against a root it
// obtained from consensus.
func VerifyProof(root []byte, p *Proof) bool {
	if p == nil || len(root) != KeySize || len(p.Key) != KeySize || len(p.Bitmap) != KeySize {
		return false
	}

	var cur []byte
	if p.Value == nil {
		cur = defaultHashes[TreeDepth]
	} else {
		cur = leafHash(p.Value)
	}

	si := 0
	for d := TreeDepth; d >= 1; d-- {
		idx := TreeDepth - d

		var sib []byte
		if bitAt(p.Bitmap, idx) {
			if si >= len(p.Siblings) {
				return false
			}
			sib = p.Siblings[si]
			si++
		} else {
			sib = defaultHashes[d]
		}
		if len(sib) != KeySize {
			return false
		}

		if bitAt(p.Key, d-1) {
			cur = internalHash(sib, cur)
		} else {
			cur = internalHash(cur, sib)
		}
	}

	// All carried siblings must have been consumed; leftovers mean the bitmap
	// and the sibling list disagree, so the proof is malformed.
	return si == len(p.Siblings) && bytes.Equal(cur, root)
}
