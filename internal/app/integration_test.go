package app

import (
	"bytes"
	"context"
	"testing"

	abci "github.com/cometbft/cometbft/abci/types"

	"github.com/ajablonsk1/blockchain-dpki/internal/state"
)

// queryProof runs the /domain/proof query and returns the response plus the
// decoded SMT proof.
func queryProof(t *testing.T, app *App, domain string) (*abci.ResponseQuery, *state.Proof) {
	t.Helper()
	res, err := app.Query(context.Background(), &abci.RequestQuery{Path: QueryPathDomainProof, Data: []byte(domain)})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if res.Code != CodeOK {
		t.Fatalf("query proof code = %d, log = %q", res.Code, res.Log)
	}
	if res.ProofOps == nil || len(res.ProofOps.Ops) != 1 {
		t.Fatalf("expected exactly one proof op, got %+v", res.ProofOps)
	}
	op := res.ProofOps.Ops[0]
	if op.Type != ProofOpType {
		t.Fatalf("proof op type = %q, want %q", op.Type, ProofOpType)
	}
	p := &state.Proof{}
	if err := p.UnmarshalBinary(op.Data); err != nil {
		t.Fatalf("decode proof: %v", err)
	}
	return res, p
}

// TestFullFlow exercises the end-to-end lifecycle the thesis claims as its core
// contribution: register a domain, fetch a proof, verify it OFFLINE against the
// app hash (no tree access), revoke, and confirm the root moved and the old
// proof no longer verifies.
func TestFullFlow_RegisterProofRevoke(t *testing.T) {
	app := newTestApp(t)
	priv, pub := keypair(t)
	const domain = "example.com"

	// Genesis.
	if _, err := app.InitChain(context.Background(), &abci.RequestInitChain{ChainId: testChainID}); err != nil {
		t.Fatalf("InitChain: %v", err)
	}

	// Register.
	rootAfterRegister := finalize(t, app, 1, signedRegister(t, priv, pub, domain)).AppHash

	// Query with proof and verify it offline against the committed root.
	_, proof := queryProof(t, app, domain)
	ds, present, err := state.VerifyDomainProof(rootAfterRegister, domain, proof)
	if err != nil {
		t.Fatalf("VerifyDomainProof (inclusion): %v", err)
	}
	if !present {
		t.Fatal("inclusion proof verified as absent")
	}
	if ds.GetCertificate().GetDomain() != domain {
		t.Fatalf("proven domain = %q", ds.GetCertificate().GetDomain())
	}

	// A non-inclusion proof for an unrelated domain must also verify.
	_, absentProof := queryProof(t, app, "other.example.org")
	if _, present, err := state.VerifyDomainProof(rootAfterRegister, "other.example.org", absentProof); err != nil || present {
		t.Fatalf("non-inclusion verify: present=%v err=%v", present, err)
	}

	// Revoke and confirm the app hash changed.
	rootAfterRevoke := finalize(t, app, 2, signedRevoke(t, priv, domain, 1, "compromised")).AppHash
	if bytes.Equal(rootAfterRegister, rootAfterRevoke) {
		t.Fatal("app hash unchanged after revoke")
	}

	// The pre-revoke inclusion proof must NOT verify against the new root: this
	// is what makes a stale binding undetectably-replayable impossible.
	if _, _, err := state.VerifyDomainProof(rootAfterRevoke, domain, proof); err == nil {
		t.Fatal("stale proof verified against new root")
	}

	// A fresh proof against the new root shows the revoked state.
	_, freshProof := queryProof(t, app, domain)
	ds, present, err = state.VerifyDomainProof(rootAfterRevoke, domain, freshProof)
	if err != nil || !present {
		t.Fatalf("fresh inclusion verify: present=%v err=%v", present, err)
	}
	if !ds.GetRevoked() {
		t.Fatal("fresh proof does not reflect revocation")
	}
}

func TestQuery_UnknownPath(t *testing.T) {
	app := newTestApp(t)
	res, err := app.Query(context.Background(), &abci.RequestQuery{Path: "/bogus"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if res.Code != CodeUnknownQuery {
		t.Fatalf("unknown path code = %d, want %d", res.Code, CodeUnknownQuery)
	}
}

func TestInfo_ReportsHeightAndHash(t *testing.T) {
	app := newTestApp(t)
	priv, pub := keypair(t)
	finalize(t, app, 7, signedRegister(t, priv, pub, "example.com"))

	res, err := app.Info(context.Background(), &abci.RequestInfo{})
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if res.LastBlockHeight != 7 {
		t.Fatalf("LastBlockHeight = %d, want 7", res.LastBlockHeight)
	}
	if len(res.LastBlockAppHash) != state.KeySize {
		t.Fatalf("app hash length = %d, want %d", len(res.LastBlockAppHash), state.KeySize)
	}
	if res.Data != AppName {
		t.Fatalf("Data = %q, want %q", res.Data, AppName)
	}
}
