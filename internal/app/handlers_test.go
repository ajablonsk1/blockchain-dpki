package app

import (
	"testing"
)

func TestRegister_Success(t *testing.T) {
	app := newTestApp(t)
	priv, pub := keypair(t)

	res := finalize(t, app, 1, signedRegister(t, priv, pub, "example.com"))
	if got := res.TxResults[0]; got.Code != CodeOK {
		t.Fatalf("register code = %d, log = %q", got.Code, got.Log)
	}

	ds := queryDomainState(t, app, "example.com")
	if ds == nil {
		t.Fatal("domain not found after register")
	}
	if ds.GetCertificate().GetDomain() != "example.com" {
		t.Fatalf("domain = %q", ds.GetCertificate().GetDomain())
	}
	if ds.GetNonce() != 0 {
		t.Fatalf("nonce after register = %d, want 0", ds.GetNonce())
	}
	if ds.GetRevoked() {
		t.Fatal("freshly registered domain is revoked")
	}
}

func TestRegister_DuplicateRejected(t *testing.T) {
	app := newTestApp(t)
	priv, pub := keypair(t)

	finalize(t, app, 1, signedRegister(t, priv, pub, "example.com"))
	res := finalize(t, app, 2, signedRegister(t, priv, pub, "example.com"))
	if res.TxResults[0].Code != CodeSemantic {
		t.Fatalf("duplicate register code = %d, want %d", res.TxResults[0].Code, CodeSemantic)
	}
}

func TestRevoke_Success(t *testing.T) {
	app := newTestApp(t)
	priv, pub := keypair(t)

	finalize(t, app, 1, signedRegister(t, priv, pub, "example.com"))
	res := finalize(t, app, 2, signedRevoke(t, priv, "example.com", 1, "key compromised"))
	if res.TxResults[0].Code != CodeOK {
		t.Fatalf("revoke code = %d, log = %q", res.TxResults[0].Code, res.TxResults[0].Log)
	}

	ds := queryDomainState(t, app, "example.com")
	if !ds.GetRevoked() {
		t.Fatal("domain not revoked")
	}
	if ds.GetNonce() != 1 {
		t.Fatalf("nonce after revoke = %d, want 1", ds.GetNonce())
	}
	if ds.GetRevokeReason() != "key compromised" {
		t.Fatalf("reason = %q", ds.GetRevokeReason())
	}
	if ds.GetRevokedAt() != testBlockTime.Unix() {
		t.Fatalf("revoked_at = %d, want %d", ds.GetRevokedAt(), testBlockTime.Unix())
	}
}

func TestRevoke_UnknownDomainRejected(t *testing.T) {
	app := newTestApp(t)
	priv, _ := keypair(t)

	res := finalize(t, app, 1, signedRevoke(t, priv, "nope.com", 1, ""))
	// Signature verification looks up the owner key first; an absent domain
	// fails there.
	if res.TxResults[0].Code != CodeSignature {
		t.Fatalf("revoke of unknown domain code = %d, want %d", res.TxResults[0].Code, CodeSignature)
	}
}

func TestRevoke_DoubleRevokeRejected(t *testing.T) {
	app := newTestApp(t)
	priv, pub := keypair(t)

	finalize(t, app, 1, signedRegister(t, priv, pub, "example.com"))
	finalize(t, app, 2, signedRevoke(t, priv, "example.com", 1, ""))
	res := finalize(t, app, 3, signedRevoke(t, priv, "example.com", 2, ""))
	if res.TxResults[0].Code != CodeSemantic {
		t.Fatalf("double revoke code = %d, want %d", res.TxResults[0].Code, CodeSemantic)
	}
}

func TestRevoke_WrongNonceRejected(t *testing.T) {
	app := newTestApp(t)
	priv, pub := keypair(t)

	finalize(t, app, 1, signedRegister(t, priv, pub, "example.com"))
	// First mutation must use nonce 1; nonce 5 is wrong.
	res := finalize(t, app, 2, signedRevoke(t, priv, "example.com", 5, ""))
	if res.TxResults[0].Code != CodeSemantic {
		t.Fatalf("wrong-nonce revoke code = %d, want %d", res.TxResults[0].Code, CodeSemantic)
	}
}

func TestRotate_Success(t *testing.T) {
	app := newTestApp(t)
	priv, pub := keypair(t)
	newPriv, newPub := keypair(t)

	finalize(t, app, 1, signedRegister(t, priv, pub, "example.com"))
	res := finalize(t, app, 2, signedRotate(t, priv, "example.com", 1, newPub))
	if res.TxResults[0].Code != CodeOK {
		t.Fatalf("rotate code = %d, log = %q", res.TxResults[0].Code, res.TxResults[0].Log)
	}

	ds := queryDomainState(t, app, "example.com")
	if ds.GetCertificate().GetVersion() != 1 {
		t.Fatalf("cert version after rotate = %d, want 1", ds.GetCertificate().GetVersion())
	}
	if string(ds.GetCertificate().GetPublicKey()) != string(newPub) {
		t.Fatal("public key not rotated")
	}

	// The new key must now be the one that authorizes further mutations.
	res2 := finalize(t, app, 3, signedRevoke(t, newPriv, "example.com", 2, "rotated then revoked"))
	if res2.TxResults[0].Code != CodeOK {
		t.Fatalf("revoke with rotated key code = %d, log = %q", res2.TxResults[0].Code, res2.TxResults[0].Log)
	}
}

func TestRotate_RevokedDomainRejected(t *testing.T) {
	app := newTestApp(t)
	priv, pub := keypair(t)
	_, newPub := keypair(t)

	finalize(t, app, 1, signedRegister(t, priv, pub, "example.com"))
	finalize(t, app, 2, signedRevoke(t, priv, "example.com", 1, ""))
	res := finalize(t, app, 3, signedRotate(t, priv, "example.com", 2, newPub))
	if res.TxResults[0].Code != CodeSemantic {
		t.Fatalf("rotate of revoked domain code = %d, want %d", res.TxResults[0].Code, CodeSemantic)
	}
}

func TestFinalizeBlock_AppHashChangesWithState(t *testing.T) {
	app := newTestApp(t)
	priv, pub := keypair(t)

	empty := finalize(t, app, 1).AppHash
	afterReg := finalize(t, app, 2, signedRegister(t, priv, pub, "example.com")).AppHash

	if string(empty) == string(afterReg) {
		t.Fatal("app hash did not change after register")
	}
}
