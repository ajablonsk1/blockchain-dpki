package state

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"

	"github.com/ajablonsk1/blockchain-dpki/internal/crypto"
)

// testKey returns a deterministic 32-byte key derived from i.
func testKey(i int) []byte {
	return crypto.Hash(fmt.Appendf(nil, "key-%d", i))
}

func testVal(i int) []byte {
	return fmt.Appendf(nil, "value-%d", i)
}

func newSMT() *SMT { return NewSMT(NewMemoryStore()) }

func mustRoot(t *testing.T, s *SMT) []byte {
	t.Helper()
	r, err := s.Root()
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	return r
}

func TestSMT_EmptyRootIsDefault(t *testing.T) {
	s := newSMT()
	if !bytes.Equal(mustRoot(t, s), defaultHashes[0]) {
		t.Fatal("empty tree root must equal defaultHashes[0]")
	}
}

func TestSMT_SetGetHasDelete(t *testing.T) {
	s := newSMT()
	key, val := testKey(1), testVal(1)

	if has, _ := s.Has(key); has {
		t.Fatal("Has on empty tree = true")
	}

	if err := s.Set(key, val); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, ok, err := s.Get(key)
	if err != nil || !ok {
		t.Fatalf("Get after Set: ok=%v err=%v", ok, err)
	}
	if !bytes.Equal(got, val) {
		t.Fatalf("Get = %q, want %q", got, val)
	}

	if err := s.Delete(key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok, _ := s.Get(key); ok {
		t.Fatal("Get after Delete = present")
	}
}

func TestSMT_RejectsWrongKeyLength(t *testing.T) {
	s := newSMT()
	short := []byte("too-short")
	if err := s.Set(short, []byte("v")); err != ErrInvalidKeyLength {
		t.Fatalf("Set wrong length err = %v, want ErrInvalidKeyLength", err)
	}
	if _, _, err := s.Get(short); err != ErrInvalidKeyLength {
		t.Fatalf("Get wrong length err = %v, want ErrInvalidKeyLength", err)
	}
	if _, err := s.Prove(short); err != ErrInvalidKeyLength {
		t.Fatalf("Prove wrong length err = %v, want ErrInvalidKeyLength", err)
	}
}

// TestSMT_DeterministicAcrossInsertionOrder is the core property test: the same
// set of key/value pairs must produce the same root regardless of the order in
// which they were inserted, and regardless of which instance computed it.
func TestSMT_DeterministicAcrossInsertionOrder(t *testing.T) {
	const n = 200
	order1 := rand.New(rand.NewSource(1)).Perm(n)
	order2 := rand.New(rand.NewSource(2)).Perm(n)

	s1, s2 := newSMT(), newSMT()
	for _, i := range order1 {
		if err := s1.Set(testKey(i), testVal(i)); err != nil {
			t.Fatalf("s1.Set: %v", err)
		}
	}
	for _, i := range order2 {
		if err := s2.Set(testKey(i), testVal(i)); err != nil {
			t.Fatalf("s2.Set: %v", err)
		}
	}

	if !bytes.Equal(mustRoot(t, s1), mustRoot(t, s2)) {
		t.Fatal("root depends on insertion order — non-deterministic")
	}
}

// TestSMT_DeleteRestoresRoot verifies that inserting then deleting a key returns
// the tree to the exact root it had before — proof that deletion collapses the
// path back to default hashes (no residue).
func TestSMT_DeleteRestoresRoot(t *testing.T) {
	s := newSMT()
	for i := range 10 {
		if err := s.Set(testKey(i), testVal(i)); err != nil {
			t.Fatalf("Set: %v", err)
		}
	}
	before := mustRoot(t, s)

	if err := s.Set(testKey(999), testVal(999)); err != nil {
		t.Fatalf("Set extra: %v", err)
	}
	if bytes.Equal(before, mustRoot(t, s)) {
		t.Fatal("root unchanged after inserting a new key")
	}

	if err := s.Delete(testKey(999)); err != nil {
		t.Fatalf("Delete extra: %v", err)
	}
	if !bytes.Equal(before, mustRoot(t, s)) {
		t.Fatal("root not restored after deleting the extra key")
	}
}

// TestSMT_UpdateValueChangesRootIdempotently checks that changing a value moves
// the root, and re-setting the identical value is a no-op for the root.
func TestSMT_UpdateValueChangesRootIdempotently(t *testing.T) {
	s := newSMT()
	key := testKey(1)
	if err := s.Set(key, []byte("v1")); err != nil {
		t.Fatalf("Set v1: %v", err)
	}
	r1 := mustRoot(t, s)

	if err := s.Set(key, []byte("v2")); err != nil {
		t.Fatalf("Set v2: %v", err)
	}
	r2 := mustRoot(t, s)
	if bytes.Equal(r1, r2) {
		t.Fatal("root unchanged after updating value")
	}

	if err := s.Set(key, []byte("v2")); err != nil {
		t.Fatalf("Set v2 again: %v", err)
	}
	if !bytes.Equal(r2, mustRoot(t, s)) {
		t.Fatal("re-setting the same value changed the root")
	}
}

// TestSMT_NodeStoreCanonical checks that two trees holding identical content
// also hold an identical number of persisted nodes, i.e. deletion does not leak
// stale nodes that would diverge the backends.
func TestSMT_NodeStoreCanonical(t *testing.T) {
	build := func() *MemoryStore {
		m := NewMemoryStore()
		s := NewSMT(m)
		for i := range 50 {
			_ = s.Set(testKey(i), testVal(i))
		}
		return m
	}
	clean := build()

	churned := NewMemoryStore()
	s := NewSMT(churned)
	for i := range 50 {
		_ = s.Set(testKey(i), testVal(i))
	}
	// Insert and delete extra keys; the store must return to the clean size.
	for i := 1000; i < 1020; i++ {
		_ = s.Set(testKey(i), testVal(i))
	}
	for i := 1000; i < 1020; i++ {
		_ = s.Delete(testKey(i))
	}

	if clean.Len() != churned.Len() {
		t.Fatalf("churned store has %d entries, clean has %d", churned.Len(), clean.Len())
	}
}
