package types

import (
	"errors"
	"testing"

	"github.com/ajablonsk1/blockchain-dpki/internal/crypto"
)

func newCert(t *testing.T) *Certificate {
	t.Helper()

	_, pub, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	return &Certificate{
		Domain:    "example.com",
		PublicKey: pub,
		Algorithm: Algorithm_ALGORITHM_ED25519,
		ValidFrom: MinValidTimestamp,
	}
}

func TestCertificate_SignBytes_NilCert(t *testing.T) {
	var c *Certificate
	_, err := c.SignBytes()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrNilCertificate) {
		t.Fatalf("expected ErrNilCertificate, got: %v", err)
	}
}

func TestCertificate_SignBytes_NonEmpty(t *testing.T) {
	c := newCert(t)

	b, err := c.SignBytes()
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("SignBytes returned empty bytes for non-empty certificate")
	}
}

func TestCertificate_SignBytes_Deterministic(t *testing.T) {
	c := newCert(t)

	b1, err := c.SignBytes()
	if err != nil {
		t.Fatalf("first SignBytes: %v", err)
	}

	b2, err := c.SignBytes()
	if err != nil {
		t.Fatalf("second SignBytes: %v", err)
	}

	if string(b1) != string(b2) {
		t.Fatal("SignBytes is not deterministic")
	}
}

func TestCertificate_SignBytes_DifferentCerts(t *testing.T) {
	c1 := newCert(t)
	c2 := newCert(t)
	c2.Domain = "other.com"

	b1, _ := c1.SignBytes()
	b2, _ := c2.SignBytes()

	if string(b1) == string(b2) {
		t.Fatal("distinct certificates produced identical SignBytes")
	}
}

func TestCertificate_Hash_NilCert(t *testing.T) {
	var c *Certificate
	_, err := c.Hash()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrNilCertificate) {
		t.Fatalf("expected ErrNilCertificate, got: %v", err)
	}
}

func TestCertificate_Hash_Length(t *testing.T) {
	c := newCert(t)

	h, err := c.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if len(h) != 32 {
		t.Fatalf("Hash length: got %d, want 32", len(h))
	}
}

func TestCertificate_Hash_Deterministic(t *testing.T) {
	c := newCert(t)

	h1, _ := c.Hash()
	h2, _ := c.Hash()

	if string(h1) != string(h2) {
		t.Fatal("Hash is not deterministic")
	}
}

func TestCertificate_Hash_DifferentCerts(t *testing.T) {
	c1 := newCert(t)
	c2 := newCert(t)
	c2.Domain = "other.com"

	h1, _ := c1.Hash()
	h2, _ := c2.Hash()

	if string(h1) == string(h2) {
		t.Fatal("distinct certificates produced the same hash")
	}
}

func TestCertificate_Hash_MatchesSignBytes(t *testing.T) {
	c := newCert(t)

	sb, err := c.SignBytes()
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}

	h, err := c.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	want := crypto.Hash(sb)
	if string(h) != string(want) {
		t.Fatal("Hash does not equal SHA-256(SignBytes)")
	}
}
