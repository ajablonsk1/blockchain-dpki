package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestHash_OutputLength(t *testing.T) {
	got := Hash([]byte("hello"))
	if len(got) != 32 {
		t.Fatalf("Hash length: got %d, want 32", len(got))
	}
}

func TestHash_KnownValue(t *testing.T) {
	raw := sha256.Sum256([]byte("hello"))
	want := raw[:]

	got := Hash([]byte("hello"))

	if string(got) != string(want) {
		t.Fatalf("Hash mismatch: got %x, want %x", got, want)
	}
}

func TestHash_EmptyInput(t *testing.T) {
	got := Hash([]byte{})
	if len(got) != 32 {
		t.Fatalf("Hash of empty input: got %d bytes, want 32", len(got))
	}
}

func TestHash_Deterministic(t *testing.T) {
	data := []byte("deterministic input")
	h1 := Hash(data)
	h2 := Hash(data)

	if string(h1) != string(h2) {
		t.Fatal("Hash is not deterministic")
	}
}

func TestHash_DifferentInputs_DifferentOutputs(t *testing.T) {
	h1 := Hash([]byte("foo"))
	h2 := Hash([]byte("bar"))

	if string(h1) == string(h2) {
		t.Fatal("distinct inputs produced the same hash")
	}
}

func TestFingerprint_Length(t *testing.T) {
	key := make([]byte, Ed25519PublicKeySize)
	got := Fingerprint(key)

	if len(got) != 64 {
		t.Fatalf("Fingerprint length: got %d, want 64 hex chars", len(got))
	}
}

func TestFingerprint_IsHex(t *testing.T) {
	key := make([]byte, Ed25519PublicKeySize)
	got := Fingerprint(key)

	if _, err := hex.DecodeString(got); err != nil {
		t.Fatalf("Fingerprint is not valid hex: %v", err)
	}
}

func TestFingerprint_MatchesHash(t *testing.T) {
	key := []byte("some public key bytes")
	want := hex.EncodeToString(Hash(key))
	got := Fingerprint(key)

	if got != want {
		t.Fatalf("Fingerprint mismatch: got %q, want %q", got, want)
	}
}

func TestFingerprint_Deterministic(t *testing.T) {
	key := make([]byte, Ed25519PublicKeySize)
	f1 := Fingerprint(key)
	f2 := Fingerprint(key)

	if f1 != f2 {
		t.Fatal("Fingerprint is not deterministic")
	}
}
