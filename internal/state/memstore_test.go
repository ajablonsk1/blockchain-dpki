package state

import (
	"bytes"
	"errors"
	"testing"
)

func TestMemoryStore_RoundTrip(t *testing.T) {
	m := NewMemoryStore()

	if _, err := m.Get([]byte("missing")); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Get(missing) error = %v, want ErrKeyNotFound", err)
	}

	if err := m.Set([]byte("k"), []byte("v")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := m.Get([]byte("k"))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, []byte("v")) {
		t.Fatalf("Get = %q, want %q", got, "v")
	}

	if err := m.Delete([]byte("k")); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := m.Get([]byte("k")); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Get after delete error = %v, want ErrKeyNotFound", err)
	}

	// Deleting an absent key is a no-op.
	if err := m.Delete([]byte("k")); err != nil {
		t.Fatalf("Delete absent: %v", err)
	}
}

// TestMemoryStore_CopiesValues guards the contract that the store does not alias
// caller buffers: mutating the slice passed to Set or returned by Get must not
// change what is stored. Aliasing here would silently corrupt tree nodes.
func TestMemoryStore_CopiesValues(t *testing.T) {
	m := NewMemoryStore()
	val := []byte("original")
	if err := m.Set([]byte("k"), val); err != nil {
		t.Fatalf("Set: %v", err)
	}
	val[0] = 'X' // mutate caller's buffer after Set

	got, err := m.Get([]byte("k"))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, []byte("original")) {
		t.Fatalf("stored value aliased caller buffer: got %q", got)
	}

	got[0] = 'Y' // mutate returned buffer
	again, _ := m.Get([]byte("k"))
	if !bytes.Equal(again, []byte("original")) {
		t.Fatalf("returned value aliased stored buffer: got %q", again)
	}
}
