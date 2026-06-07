package app

import (
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/ajablonsk1/blockchain-dpki/internal/types"
)

// The tests below map to the STRIDE categories used in the thesis security
// analysis. Each asserts that an attack is rejected — by CheckTx cheaply at the
// mempool, and/or by FinalizeBlock authoritatively — without mutating state.

// Spoofing: a revoke signed by a key other than the domain owner's must fail.
func TestSTRIDE_Spoofing_WrongSignerRejected(t *testing.T) {
	app := newTestApp(t)
	ownerPriv, ownerPub := keypair(t)
	attackerPriv, _ := keypair(t)

	finalize(t, app, 1, signedRegister(t, ownerPriv, ownerPub, "example.com"))

	// Attacker signs a revoke for a domain they do not own.
	badRevoke := signedRevoke(t, attackerPriv, "example.com", 1, "")
	if c := checkTx(t, app, badRevoke).Code; c != CodeSignature {
		t.Fatalf("CheckTx spoofed revoke code = %d, want %d", c, CodeSignature)
	}
	res := finalize(t, app, 2, badRevoke)
	if res.TxResults[0].Code != CodeSignature {
		t.Fatalf("FinalizeBlock spoofed revoke code = %d, want %d", res.TxResults[0].Code, CodeSignature)
	}
	if queryDomainState(t, app, "example.com").GetRevoked() {
		t.Fatal("spoofed revoke mutated state")
	}
}

// Spoofing variant: a register whose certificate key does not match the signing
// key must fail (the signature is checked against the certificate's own key).
func TestSTRIDE_Spoofing_CertKeyMismatchRejected(t *testing.T) {
	app := newTestApp(t)
	signerPriv, _ := keypair(t)
	_, otherPub := keypair(t)

	// Certificate advertises otherPub but the tx is signed by signerPriv.
	cert, err := types.NewCertificate("example.com", otherPub, types.Algorithm_ALGORITHM_ED25519, testValidFrom)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := types.NewRegisterTx(cert, testChainID)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Sign(signerPriv); err != nil {
		t.Fatal(err)
	}
	raw := marshalTx(t, tx)

	if c := checkTx(t, app, raw).Code; c != CodeSignature {
		t.Fatalf("mismatched register code = %d, want %d", c, CodeSignature)
	}
}

// Tampering: modifying a signed transaction's payload invalidates its signature.
func TestSTRIDE_Tampering_PayloadMutationDetected(t *testing.T) {
	app := newTestApp(t)
	priv, pub := keypair(t)
	raw := signedRegister(t, priv, pub, "example.com")

	// Decode, change the domain, re-encode WITHOUT re-signing.
	tx := &types.Transaction{}
	if err := proto.Unmarshal(raw, tx); err != nil {
		t.Fatal(err)
	}
	tx.GetRegister().GetCertificate().Domain = "evil.com"
	tampered := marshalTx(t, tx)

	if c := checkTx(t, app, tampered).Code; c != CodeSignature {
		t.Fatalf("tampered tx code = %d, want %d", c, CodeSignature)
	}
}

// Denial of service: garbage bytes are rejected cheaply at decode time, before
// any cryptographic work.
func TestSTRIDE_DoS_GarbageRejectedCheaply(t *testing.T) {
	app := newTestApp(t)
	if c := checkTx(t, app, []byte("not a protobuf transaction")).Code; c != CodeDecode {
		t.Fatalf("garbage tx code = %d, want %d", c, CodeDecode)
	}
}

// Elevation of privilege: replaying a mutation (reusing a nonce) must fail. After
// one rotate at nonce 1, replaying the same signed bytes is rejected.
func TestSTRIDE_EoP_ReplayRejected(t *testing.T) {
	app := newTestApp(t)
	priv, pub := keypair(t)
	_, newPub := keypair(t)

	finalize(t, app, 1, signedRegister(t, priv, pub, "example.com"))

	rotate := signedRotate(t, priv, "example.com", 1, newPub)
	if res := finalize(t, app, 2, rotate); res.TxResults[0].Code != CodeOK {
		t.Fatalf("first rotate code = %d", res.TxResults[0].Code)
	}
	// Replay the exact same bytes: nonce 1 is now stale.
	res := finalize(t, app, 3, rotate)
	if res.TxResults[0].Code == CodeOK {
		t.Fatal("replayed rotate was accepted")
	}
}

// Elevation of privilege variant: registering an already-owned domain is rejected.
func TestSTRIDE_EoP_DomainHijackRejected(t *testing.T) {
	app := newTestApp(t)
	ownerPriv, ownerPub := keypair(t)
	attackerPriv, attackerPub := keypair(t)

	finalize(t, app, 1, signedRegister(t, ownerPriv, ownerPub, "example.com"))

	// Attacker tries to re-register the same domain with their own key.
	hijack := signedRegister(t, attackerPriv, attackerPub, "example.com")
	if c := checkTx(t, app, hijack).Code; c != CodeSemantic {
		t.Fatalf("CheckTx hijack code = %d, want %d", c, CodeSemantic)
	}
	res := finalize(t, app, 2, hijack)
	if res.TxResults[0].Code != CodeSemantic {
		t.Fatalf("FinalizeBlock hijack code = %d, want %d", res.TxResults[0].Code, CodeSemantic)
	}
	// The original owner's key still controls the domain.
	ds := queryDomainState(t, app, "example.com")
	if string(ds.GetCertificate().GetPublicKey()) != string(ownerPub) {
		t.Fatal("hijack replaced the owner key")
	}
}

// Wrong chain id: a transaction signed for another chain is rejected, preventing
// cross-chain replay.
func TestSTRIDE_CrossChainReplayRejected(t *testing.T) {
	app := newTestApp(t)
	priv, pub := keypair(t)

	cert, err := types.NewCertificate("example.com", pub, types.Algorithm_ALGORITHM_ED25519, testValidFrom)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := types.NewRegisterTx(cert, "other-chain")
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Sign(priv); err != nil {
		t.Fatal(err)
	}
	raw := marshalTx(t, tx)

	if c := checkTx(t, app, raw).Code; c != CodeChainID {
		t.Fatalf("wrong-chain code = %d, want %d", c, CodeChainID)
	}
}
