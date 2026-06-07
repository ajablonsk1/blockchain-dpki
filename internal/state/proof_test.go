package state

import (
	"bytes"
	"testing"
)

func TestProof_InclusionVerifies(t *testing.T) {
	s := newSMT()
	for i := range 64 {
		if err := s.Set(testKey(i), testVal(i)); err != nil {
			t.Fatalf("Set: %v", err)
		}
	}
	root := mustRoot(t, s)

	for i := range 64 {
		p, err := s.Prove(testKey(i))
		if err != nil {
			t.Fatalf("Prove(%d): %v", i, err)
		}
		if !p.IsInclusion() {
			t.Fatalf("Prove(%d) is not an inclusion proof", i)
		}
		if !bytes.Equal(p.Value, testVal(i)) {
			t.Fatalf("proof value = %q, want %q", p.Value, testVal(i))
		}
		if !VerifyProof(root, p) {
			t.Fatalf("inclusion proof for key %d did not verify", i)
		}
	}
}

// TestProof_CompressionIsEffective documents that compressed proofs are far
// smaller than the naive 256-sibling proof: with a handful of keys, almost all
// siblings are default and omitted.
func TestProof_CompressionIsEffective(t *testing.T) {
	s := newSMT()
	for i := range 8 {
		_ = s.Set(testKey(i), testVal(i))
	}
	p, err := s.Prove(testKey(0))
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}
	// With 8 keys the populated subtree is shallow; a correct compression keeps
	// the carried sibling count well below the full depth.
	if len(p.Siblings) >= TreeDepth/2 {
		t.Fatalf("compression ineffective: %d siblings carried", len(p.Siblings))
	}
}

func TestProof_NonInclusionVerifies(t *testing.T) {
	s := newSMT()
	for i := range 64 {
		_ = s.Set(testKey(i), testVal(i))
	}
	root := mustRoot(t, s)

	absent := testKey(99999)
	p, err := s.Prove(absent)
	if err != nil {
		t.Fatalf("Prove absent: %v", err)
	}
	if p.IsInclusion() {
		t.Fatal("expected a non-inclusion proof for an absent key")
	}
	if !VerifyProof(root, p) {
		t.Fatal("non-inclusion proof did not verify")
	}
}

// TestProof_PresenceAndAbsenceAreExclusive checks that a non-inclusion proof
// stops verifying once the key is inserted, and an inclusion proof stops
// verifying once the key is deleted — against the matching root each time.
func TestProof_PresenceAndAbsenceAreExclusive(t *testing.T) {
	s := newSMT()
	key := testKey(7)

	absentProof, _ := s.Prove(key)
	if !VerifyProof(mustRoot(t, s), absentProof) {
		t.Fatal("non-inclusion proof failed on empty tree")
	}

	if err := s.Set(key, testVal(7)); err != nil {
		t.Fatalf("Set: %v", err)
	}
	rootAfterSet := mustRoot(t, s)

	// The old non-inclusion proof must not verify against the new root.
	if VerifyProof(rootAfterSet, absentProof) {
		t.Fatal("stale non-inclusion proof verified after the key was inserted")
	}

	inclProof, _ := s.Prove(key)
	if !VerifyProof(rootAfterSet, inclProof) {
		t.Fatal("inclusion proof failed after Set")
	}

	if err := s.Delete(key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if VerifyProof(mustRoot(t, s), inclProof) {
		t.Fatal("stale inclusion proof verified after the key was deleted")
	}
}

func TestProof_TamperingIsDetected(t *testing.T) {
	s := newSMT()
	for i := range 32 {
		_ = s.Set(testKey(i), testVal(i))
	}
	root := mustRoot(t, s)

	base, err := s.Prove(testKey(5))
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}
	if !VerifyProof(root, base) {
		t.Fatal("baseline proof did not verify")
	}

	t.Run("tampered value", func(t *testing.T) {
		p := cloneProof(base)
		p.Value = append(append([]byte(nil), p.Value...), '!')
		if VerifyProof(root, p) {
			t.Fatal("verified a proof with a tampered value")
		}
	})

	t.Run("tampered sibling", func(t *testing.T) {
		p := cloneProof(base)
		if len(p.Siblings) == 0 {
			t.Skip("no siblings to tamper")
		}
		p.Siblings[0] = append([]byte(nil), p.Siblings[0]...)
		p.Siblings[0][0] ^= 0xFF
		if VerifyProof(root, p) {
			t.Fatal("verified a proof with a tampered sibling")
		}
	})

	t.Run("wrong root", func(t *testing.T) {
		bad := append([]byte(nil), root...)
		bad[0] ^= 0xFF
		if VerifyProof(bad, base) {
			t.Fatal("verified a proof against the wrong root")
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		p := cloneProof(base)
		p.Key = testKey(6) // proof body is for key 5
		if VerifyProof(root, p) {
			t.Fatal("verified a proof with a swapped key")
		}
	})

	t.Run("bitmap sibling mismatch", func(t *testing.T) {
		p := cloneProof(base)
		p.Siblings = p.Siblings[:0] // claim no siblings while bitmap has bits set
		if VerifyProof(root, p) {
			t.Fatal("verified a proof whose bitmap and siblings disagree")
		}
	})
}

func TestVerifyProof_RejectsMalformed(t *testing.T) {
	good := []byte(bytes.Repeat([]byte{1}, KeySize))
	cases := map[string]*Proof{
		"nil proof":         nil,
		"short key":         {Key: []byte{1}, Bitmap: make([]byte, KeySize)},
		"short bitmap":      {Key: good, Bitmap: []byte{1}},
		"non-inclusion ok?": {Key: good, Bitmap: make([]byte, KeySize)}, // valid shape, wrong root
	}
	root := make([]byte, KeySize)
	for name, p := range cases {
		if VerifyProof(root, p) {
			t.Fatalf("%s: VerifyProof returned true, want false", name)
		}
	}
}

func cloneProof(p *Proof) *Proof {
	cp := &Proof{
		Key:    append([]byte(nil), p.Key...),
		Bitmap: append([]byte(nil), p.Bitmap...),
	}
	if p.Value != nil {
		cp.Value = append([]byte(nil), p.Value...)
	}
	for _, s := range p.Siblings {
		cp.Siblings = append(cp.Siblings, append([]byte(nil), s...))
	}
	return cp
}
