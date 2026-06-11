package client

import (
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/ajablonsk1/blockchain-dpki/internal/state"
	"github.com/ajablonsk1/blockchain-dpki/internal/testhelpers"
	"github.com/ajablonsk1/blockchain-dpki/internal/types"
)

// TestProofBundleRoundTrip checks that a bundle written by lookup --save-proof
// still verifies after a save/load cycle.
func TestProofBundleRoundTrip(t *testing.T) {
	const domain = "example.com"

	smt := state.NewSMT(state.NewMemoryStore())
	_, pub := testhelpers.MustGenerateKeyPair(t)
	cert := testhelpers.MustNewCertificate(t, domain, pub)
	if err := smt.SetDomain(domain, &types.DomainState{Certificate: cert}); err != nil {
		t.Fatalf("SetDomain: %v", err)
	}
	proof, err := smt.ProveDomain(domain)
	if err != nil {
		t.Fatalf("ProveDomain: %v", err)
	}
	root, err := smt.Root()
	if err != nil {
		t.Fatalf("Root: %v", err)
	}

	bundle, err := NewProofBundle("test-chain", &DomainProof{Domain: domain, Proof: proof, Height: 7}, root)
	if err != nil {
		t.Fatalf("NewProofBundle: %v", err)
	}

	path := filepath.Join(t.TempDir(), "proof.json")
	if err := bundle.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := LoadProofBundle(path)
	if err != nil {
		t.Fatalf("LoadProofBundle: %v", err)
	}
	if loaded.Domain != domain || loaded.Height != 7 || loaded.ChainID != "test-chain" {
		t.Errorf("loaded bundle metadata = %+v", loaded)
	}
	if loaded.AppHash != hex.EncodeToString(root) {
		t.Errorf("loaded app hash = %s, want %s", loaded.AppHash, hex.EncodeToString(root))
	}

	decoded, err := loaded.DecodeProof()
	if err != nil {
		t.Fatalf("DecodeProof: %v", err)
	}
	ds, present, err := state.VerifyDomainProof(root, domain, decoded)
	if err != nil || !present {
		t.Fatalf("VerifyDomainProof after round trip = (present=%v, err=%v)", present, err)
	}
	if ds.GetCertificate().GetDomain() != domain {
		t.Errorf("proven certificate domain = %q", ds.GetCertificate().GetDomain())
	}
}
