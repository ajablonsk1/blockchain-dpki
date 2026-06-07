package app

import (
	"context"
	"testing"

	abci "github.com/cometbft/cometbft/abci/types"
)

func TestCheckTx_AcceptsValidRegister(t *testing.T) {
	app := newTestApp(t)
	priv, pub := keypair(t)

	if c := checkTx(t, app, signedRegister(t, priv, pub, "example.com")).Code; c != CodeOK {
		t.Fatalf("valid register CheckTx code = %d, want %d", c, CodeOK)
	}
}

func TestCheckTx_AcceptsValidRevokeAndRotate(t *testing.T) {
	app := newTestApp(t)
	priv, pub := keypair(t)
	_, newPub := keypair(t)

	finalize(t, app, 1, signedRegister(t, priv, pub, "example.com"))

	if c := checkTx(t, app, signedRevoke(t, priv, "example.com", 1, "")).Code; c != CodeOK {
		t.Fatalf("valid revoke CheckTx code = %d, want %d", c, CodeOK)
	}
	if c := checkTx(t, app, signedRotate(t, priv, "example.com", 1, newPub)).Code; c != CodeOK {
		t.Fatalf("valid rotate CheckTx code = %d, want %d", c, CodeOK)
	}
}

func TestCheckTx_RejectsStaleNonce(t *testing.T) {
	app := newTestApp(t)
	priv, pub := keypair(t)

	finalize(t, app, 1, signedRegister(t, priv, pub, "example.com"))
	finalize(t, app, 2, signedRevoke(t, priv, "example.com", 1, ""))

	// Domain is now revoked; a further revoke is semantically rejected by the
	// light check (revoked domain).
	if c := checkTx(t, app, signedRevoke(t, priv, "example.com", 2, "")).Code; c != CodeSemantic {
		t.Fatalf("revoke of revoked domain CheckTx code = %d, want %d", c, CodeSemantic)
	}
}

func TestCheckTx_RejectsStaleNonceOnLiveDomain(t *testing.T) {
	app := newTestApp(t)
	priv, pub := keypair(t)
	newPriv, newPub := keypair(t)

	finalize(t, app, 1, signedRegister(t, priv, pub, "example.com"))
	// Rotate advances the nonce to 1 and moves ownership to newPriv; the domain
	// stays live (not revoked).
	finalize(t, app, 2, signedRotate(t, priv, "example.com", 1, newPub))

	// A revoke at nonce 1, signed by the current owner so it passes the signature
	// stage, is rejected by the light check because nonce 1 is no longer ahead of
	// the stored nonce (1).
	stale := signedRevoke(t, newPriv, "example.com", 1, "")
	if c := checkTx(t, app, stale).Code; c != CodeSemantic {
		t.Fatalf("stale-nonce revoke CheckTx code = %d, want %d", c, CodeSemantic)
	}
}

func TestQuery_AbsentDomain(t *testing.T) {
	app := newTestApp(t)
	res, err := app.Query(context.Background(), &abci.RequestQuery{Path: QueryPathDomain, Data: []byte("missing.com")})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if res.Code != CodeOK {
		t.Fatalf("absent query code = %d, want %d", res.Code, CodeOK)
	}
	if len(res.Value) != 0 {
		t.Fatal("absent domain returned a value")
	}
	if res.Log == "" {
		t.Fatal("absent domain query has no log")
	}
}

func TestInitChain_AdoptsGenesisChainID(t *testing.T) {
	app := newTestApp(t)
	res, err := app.InitChain(context.Background(), &abci.RequestInitChain{ChainId: "different-chain"})
	if err != nil {
		t.Fatalf("InitChain: %v", err)
	}
	if len(res.AppHash) == 0 {
		t.Fatal("InitChain returned empty app hash")
	}
	if app.chainID != "different-chain" {
		t.Fatalf("chainID = %q, want adopted genesis value", app.chainID)
	}
}
