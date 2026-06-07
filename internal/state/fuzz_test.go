package state

import (
	"bytes"
	"testing"

	"github.com/ajablonsk1/blockchain-dpki/internal/crypto"
)

// FuzzSMT drives the tree with an arbitrary stream of set/delete operations and
// asserts the core invariants on every step: the tree never panics, Get agrees
// with a reference map, every present key has an inclusion proof that verifies
// against the current root, and a key known to be absent has a non-inclusion
// proof that verifies. At the end it rebuilds an independent tree from the same
// final key set in reverse order and requires a byte-identical root, exercising
// the order-independence guarantee that consensus depends on.
func FuzzSMT(f *testing.F) {
	f.Add([]byte("\x01a\x02bc"))
	f.Add([]byte("\x01\x01\x01\x00\x01\x01"))
	f.Add(bytes.Repeat([]byte("\x01x\x01y"), 20))

	f.Fuzz(func(t *testing.T, data []byte) {
		s := NewSMT(NewMemoryStore())
		ref := map[string][]byte{} // hashed-key string -> value, present keys only

		cur := data
		take := func(n int) []byte {
			if n > len(cur) {
				n = len(cur)
			}
			b := cur[:n]
			cur = cur[n:]
			return b
		}

		for len(cur) >= 2 {
			op := take(1)[0]
			klen := int(take(1)[0]) % 16 // bounded, keeps records short
			raw := take(klen)
			key := crypto.Hash(raw) // any input -> valid 32-byte key
			ks := string(key)

			switch op % 3 {
			case 0, 1: // set (weighted to grow the tree)
				vlen := 0
				if len(cur) > 0 {
					vlen = int(take(1)[0]) % 16
				}
				val := append([]byte(nil), take(vlen)...)
				if len(val) == 0 {
					// The proof contract reserves a nil/empty value for
					// non-inclusion, so the SMT only stores non-empty values
					// (the domain layer always marshals non-empty protobufs).
					val = []byte{0x01}
				}
				if err := s.Set(key, val); err != nil {
					t.Fatalf("Set: %v", err)
				}
				ref[ks] = val

				got, present, err := s.Get(key)
				if err != nil || !present || !bytes.Equal(got, val) {
					t.Fatalf("after Set: Get=%x present=%v err=%v want %x", got, present, err, val)
				}
			case 2: // delete
				if err := s.Delete(key); err != nil {
					t.Fatalf("Delete: %v", err)
				}
				delete(ref, ks)

				if _, present, err := s.Get(key); err != nil || present {
					t.Fatalf("after Delete: present=%v err=%v want absent", present, err)
				}
			}
		}

		root, err := s.Root()
		if err != nil {
			t.Fatalf("Root: %v", err)
		}

		// Every present key must produce an inclusion proof that verifies.
		for ks, val := range ref {
			key := []byte(ks)
			p, err := s.Prove(key)
			if err != nil {
				t.Fatalf("Prove(present): %v", err)
			}
			if !p.IsInclusion() || !bytes.Equal(p.Value, val) {
				t.Fatalf("present key: inclusion=%v value=%x want %x", p.IsInclusion(), p.Value, val)
			}
			if !VerifyProof(root, p) {
				t.Fatal("inclusion proof failed to verify against root")
			}
		}

		// A key that was never inserted must produce a verifying non-inclusion proof.
		absent := crypto.Hash([]byte("fuzz-definitely-absent-key"))
		if _, ok := ref[string(absent)]; !ok {
			p, err := s.Prove(absent)
			if err != nil {
				t.Fatalf("Prove(absent): %v", err)
			}
			if p.IsInclusion() {
				t.Fatal("absent key reported as inclusion")
			}
			if !VerifyProof(root, p) {
				t.Fatal("non-inclusion proof failed to verify against root")
			}
		}

		// Order independence: rebuilding from the same final set in any order
		// must yield the identical root.
		s2 := NewSMT(NewMemoryStore())
		keys := make([]string, 0, len(ref))
		for ks := range ref {
			keys = append(keys, ks)
		}
		for i := len(keys) - 1; i >= 0; i-- {
			if err := s2.Set([]byte(keys[i]), ref[keys[i]]); err != nil {
				t.Fatalf("rebuild Set: %v", err)
			}
		}
		root2, err := s2.Root()
		if err != nil {
			t.Fatalf("rebuild Root: %v", err)
		}
		if !bytes.Equal(root, root2) {
			t.Fatalf("root depends on insertion order: %x != %x", root, root2)
		}
	})
}
