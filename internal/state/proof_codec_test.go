package state

import (
	"bytes"
	"testing"
)

// roundTrip marshals and unmarshals p and fails if the decoded proof differs.
func roundTrip(t *testing.T, p *Proof) *Proof {
	t.Helper()
	b, err := p.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	got := &Proof{}
	if err := got.UnmarshalBinary(b); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	return got
}

func TestProofCodec_InclusionRoundTrip(t *testing.T) {
	s := newSMT()
	for i := range 50 {
		if err := s.Set(testKey(i), testVal(i)); err != nil {
			t.Fatal(err)
		}
	}
	root := mustRoot(t, s)

	p, err := s.Prove(testKey(7))
	if err != nil {
		t.Fatal(err)
	}

	got := roundTrip(t, p)
	if !got.IsInclusion() || !bytes.Equal(got.Value, p.Value) {
		t.Fatalf("inclusion lost: got incl=%v value=%x", got.IsInclusion(), got.Value)
	}
	if !VerifyProof(root, got) {
		t.Fatal("decoded inclusion proof failed to verify")
	}
}

func TestProofCodec_NonInclusionRoundTrip(t *testing.T) {
	s := newSMT()
	for i := range 50 {
		if err := s.Set(testKey(i), testVal(i)); err != nil {
			t.Fatal(err)
		}
	}
	root := mustRoot(t, s)

	absent := testKey(999999)
	p, err := s.Prove(absent)
	if err != nil {
		t.Fatal(err)
	}
	if p.IsInclusion() {
		t.Fatal("expected non-inclusion proof")
	}

	got := roundTrip(t, p)
	if got.IsInclusion() {
		t.Fatal("non-inclusion lost on round-trip")
	}
	if !VerifyProof(root, got) {
		t.Fatal("decoded non-inclusion proof failed to verify")
	}
}

func TestProofCodec_EmptyTreeNonInclusion(t *testing.T) {
	s := newSMT()
	root := mustRoot(t, s)
	p, err := s.Prove(testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	got := roundTrip(t, p)
	if !VerifyProof(root, got) {
		t.Fatal("empty-tree non-inclusion proof failed to verify")
	}
}

func TestProofCodec_RejectsTruncated(t *testing.T) {
	s := newSMT()
	_ = s.Set(testKey(1), testVal(1))
	p, _ := s.Prove(testKey(1))
	b, _ := p.MarshalBinary()

	for n := range len(b) {
		got := &Proof{}
		if err := got.UnmarshalBinary(b[:n]); err == nil {
			t.Fatalf("expected error decoding truncated proof at len %d", n)
		}
	}
}

func TestProofCodec_RejectsTrailing(t *testing.T) {
	s := newSMT()
	_ = s.Set(testKey(1), testVal(1))
	p, _ := s.Prove(testKey(1))
	b, _ := p.MarshalBinary()

	got := &Proof{}
	if err := got.UnmarshalBinary(append(b, 0xff)); err == nil {
		t.Fatal("expected error decoding proof with trailing data")
	}
}
