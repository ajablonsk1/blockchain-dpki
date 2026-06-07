package state

import (
	"testing"

	"github.com/ajablonsk1/blockchain-dpki/internal/testhelpers"
	"github.com/ajablonsk1/blockchain-dpki/internal/types"
)

func domainState(t *testing.T, domain string, revoked bool) *types.DomainState {
	t.Helper()
	_, pub := testhelpers.MustGenerateKeyPair(t)
	cert := testhelpers.MustNewCertificate(t, domain, pub)
	return &types.DomainState{
		Certificate: cert,
		Nonce:       1,
		Revoked:     revoked,
	}
}

func TestDomain_SetGetRoundTrip(t *testing.T) {
	s := newSMT()
	st := domainState(t, "example.com", false)

	if err := s.SetDomain("example.com", st); err != nil {
		t.Fatalf("SetDomain: %v", err)
	}

	got, ok, err := s.GetDomain("example.com")
	if err != nil || !ok {
		t.Fatalf("GetDomain: ok=%v err=%v", ok, err)
	}
	if got.GetNonce() != 1 || got.GetCertificate().GetDomain() != "example.com" {
		t.Fatalf("GetDomain returned unexpected state: %+v", got)
	}

	if _, ok, _ := s.GetDomain("other.com"); ok {
		t.Fatal("GetDomain for absent domain reported present")
	}
}

func TestDomain_SetNilStateRejected(t *testing.T) {
	s := newSMT()
	if err := s.SetDomain("example.com", nil); err != ErrNilDomainState {
		t.Fatalf("SetDomain(nil) err = %v, want ErrNilDomainState", err)
	}
}

// TestDomain_VerifyInclusionProof exercises the full relying-party path: a client
// holding only the root and a proof recovers and trusts the DomainState.
func TestDomain_VerifyInclusionProof(t *testing.T) {
	s := newSMT()
	// Populate a few domains so the proof is non-trivial.
	for _, d := range []string{"a.com", "b.com", "c.com"} {
		if err := s.SetDomain(d, domainState(t, d, false)); err != nil {
			t.Fatalf("SetDomain(%s): %v", d, err)
		}
	}
	root := mustRoot(t, s)

	p, err := s.ProveDomain("b.com")
	if err != nil {
		t.Fatalf("ProveDomain: %v", err)
	}

	st, present, err := VerifyDomainProof(root, "b.com", p)
	if err != nil || !present {
		t.Fatalf("VerifyDomainProof: present=%v err=%v", present, err)
	}
	if st.GetCertificate().GetDomain() != "b.com" {
		t.Fatalf("verified state for wrong domain: %q", st.GetCertificate().GetDomain())
	}
}

// TestDomain_VerifyRevocationProof is the central thesis scenario: revocation is
// part of the committed state, so a single proof against the root tells a relying
// party authoritatively that a domain's certificate is revoked.
func TestDomain_VerifyRevocationProof(t *testing.T) {
	s := newSMT()
	if err := s.SetDomain("revoked.com", domainState(t, "revoked.com", true)); err != nil {
		t.Fatalf("SetDomain: %v", err)
	}
	root := mustRoot(t, s)

	p, err := s.ProveDomain("revoked.com")
	if err != nil {
		t.Fatalf("ProveDomain: %v", err)
	}
	st, present, err := VerifyDomainProof(root, "revoked.com", p)
	if err != nil || !present {
		t.Fatalf("VerifyDomainProof: present=%v err=%v", present, err)
	}
	if !st.GetRevoked() {
		t.Fatal("revocation not reflected in the proven state")
	}
}

func TestDomain_VerifyNonInclusionProof(t *testing.T) {
	s := newSMT()
	if err := s.SetDomain("present.com", domainState(t, "present.com", false)); err != nil {
		t.Fatalf("SetDomain: %v", err)
	}
	root := mustRoot(t, s)

	p, err := s.ProveDomain("absent.com")
	if err != nil {
		t.Fatalf("ProveDomain: %v", err)
	}
	st, present, err := VerifyDomainProof(root, "absent.com", p)
	if err != nil {
		t.Fatalf("VerifyDomainProof: %v", err)
	}
	if present || st != nil {
		t.Fatal("absent domain verified as present")
	}
}

// TestDomain_ProofBoundToDomain ensures a valid proof for one domain cannot be
// passed off as a proof for another — the verifier rebinds the proof to the
// queried domain's key.
func TestDomain_ProofBoundToDomain(t *testing.T) {
	s := newSMT()
	if err := s.SetDomain("a.com", domainState(t, "a.com", false)); err != nil {
		t.Fatalf("SetDomain: %v", err)
	}
	root := mustRoot(t, s)

	p, err := s.ProveDomain("a.com")
	if err != nil {
		t.Fatalf("ProveDomain: %v", err)
	}

	if _, _, err := VerifyDomainProof(root, "b.com", p); err != ErrProofKeyMismatch {
		t.Fatalf("VerifyDomainProof for wrong domain err = %v, want ErrProofKeyMismatch", err)
	}
}
