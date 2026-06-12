package app

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ajablonsk1/blockchain-dpki/internal/state"
	"github.com/ajablonsk1/blockchain-dpki/internal/types"
)

// Phase-7 security suite. Together with security_test.go (Phase 3) and the
// testnet fault-tolerance scenarios (scripts/test-testnet.sh) these tests back
// the STRIDE analysis in the thesis: each one stages a concrete attack and
// asserts both the rejection code and that state was not mutated.

// Spoofing S2: a flipped signature byte must invalidate the transaction.
func TestSTRIDE_Spoofing_ForgedSignatureRejected(t *testing.T) {
	app := newTestApp(t)
	priv, pub := keypair(t)

	raw := signedRegister(t, priv, pub, "example.com")
	tx := &types.Transaction{}
	if err := proto.Unmarshal(raw, tx); err != nil {
		t.Fatal(err)
	}
	tx.Signature[0] ^= 0xFF

	if c := checkTx(t, app, marshalTx(t, tx)).Code; c != CodeSignature {
		t.Fatalf("forged signature code = %d, want %d", c, CodeSignature)
	}
}

// Spoofing: a transaction without any signature must be rejected before
// touching state.
func TestSTRIDE_Spoofing_MissingSignatureRejected(t *testing.T) {
	app := newTestApp(t)
	_, pub := keypair(t)

	cert, err := types.NewCertificate("example.com", pub, types.Algorithm_ALGORITHM_ED25519, testValidFrom)
	if err != nil {
		t.Fatal(err)
	}
	tx := &types.Transaction{
		ChainId: testChainID,
		Body:    &types.Transaction_Register{Register: &types.RegisterTx{Certificate: cert}},
		// Signature deliberately absent.
	}

	if c := checkTx(t, app, marshalTx(t, tx)).Code; c == CodeOK {
		t.Fatal("unsigned transaction was accepted")
	}
	if _, present, _ := app.smt.GetDomain("example.com"); present {
		t.Fatal("unsigned transaction mutated state")
	}
}

// Spoofing S3: an attacker takes Alice's validly signed RevokeTx for alice.com
// and swaps the domain to bob.com. The signature was made over the original
// bytes (and bob.com is owned by a different key), so it cannot validate.
func TestSTRIDE_Spoofing_CrossDomainSwapRejected(t *testing.T) {
	app := newTestApp(t)
	alicePriv, alicePub := keypair(t)
	bobPriv, bobPub := keypair(t)

	finalize(t, app, 1,
		signedRegister(t, alicePriv, alicePub, "alice.com"),
		signedRegister(t, bobPriv, bobPub, "bob.com"))

	// Alice legitimately signs a revoke of her own domain...
	raw := signedRevoke(t, alicePriv, "alice.com", 1, "key compromised")
	tx := &types.Transaction{}
	if err := proto.Unmarshal(raw, tx); err != nil {
		t.Fatal(err)
	}
	// ...and the attacker redirects it at Bob's domain without re-signing.
	tx.GetRevoke().Domain = "bob.com"
	swapped := marshalTx(t, tx)

	if c := checkTx(t, app, swapped).Code; c != CodeSignature {
		t.Fatalf("cross-domain swap code = %d, want %d", c, CodeSignature)
	}
	res := finalize(t, app, 2, swapped)
	if res.TxResults[0].Code == CodeOK {
		t.Fatal("cross-domain swap was executed")
	}
	if queryDomainState(t, app, "bob.com").GetRevoked() {
		t.Fatal("bob.com was revoked by a signature made for alice.com")
	}
}

// Tampering T2: an attacker with direct access to a validator's storage edits
// the state behind the application's back. The Merkle commitment makes this
// detectable from outside: the root diverges, so (a) the tampered node's app
// hash no longer matches the other validators' and consensus evicts it, and
// (b) no proof from the tampered tree verifies against the honest root.
func TestSTRIDE_Tampering_DirectStateEditDetected(t *testing.T) {
	smt := state.NewSMT(state.NewMemoryStore())
	_, ownerPub := keypair(t)
	_, attackerPub := keypair(t)

	cert, err := types.NewCertificate("example.com", ownerPub, types.Algorithm_ALGORITHM_ED25519, testValidFrom)
	if err != nil {
		t.Fatal(err)
	}
	if err := smt.SetDomain("example.com", &types.DomainState{Certificate: cert}); err != nil {
		t.Fatal(err)
	}
	honestRoot, err := smt.Root()
	if err != nil {
		t.Fatal(err)
	}
	honestProof, err := smt.ProveDomain("example.com")
	if err != nil {
		t.Fatal(err)
	}

	// Backdoor write: swap the owner key without any transaction.
	tamperedCert, err := types.NewCertificate("example.com", attackerPub, types.Algorithm_ALGORITHM_ED25519, testValidFrom)
	if err != nil {
		t.Fatal(err)
	}
	if err := smt.SetDomain("example.com", &types.DomainState{Certificate: tamperedCert}); err != nil {
		t.Fatal(err)
	}
	tamperedRoot, err := smt.Root()
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(honestRoot, tamperedRoot) {
		t.Fatal("state tampering did not change the root hash")
	}
	tamperedProof, err := smt.ProveDomain("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := state.VerifyDomainProof(honestRoot, "example.com", tamperedProof); err == nil {
		t.Fatal("proof of tampered state verified against the honest root")
	}
	if _, _, err := state.VerifyDomainProof(tamperedRoot, "example.com", honestProof); err == nil {
		t.Fatal("honest proof verified against the tampered root")
	}
}

// DoS D1: a flood of malformed transactions must be rejected cheaply and must
// not affect legitimate traffic afterwards.
func TestSTRIDE_DoS_SpamDoesNotBlockLegitTraffic(t *testing.T) {
	app := newTestApp(t)

	const spam = 10_000
	padding := strings.Repeat("x", 1024)
	start := time.Now()
	for i := range spam {
		garbage := fmt.Appendf(nil, "spam-%d-%s", i, padding)
		if c := checkTx(t, app, garbage).Code; c == CodeOK {
			t.Fatalf("garbage tx %d was accepted", i)
		}
	}
	elapsed := time.Since(start)
	t.Logf("rejected %d garbage txs (1 KiB each) in %v (%.1f µs/tx)",
		spam, elapsed.Round(time.Millisecond), float64(elapsed.Microseconds())/spam)

	// The system stays responsive for a legitimate registration.
	priv, pub := keypair(t)
	legit := signedRegister(t, priv, pub, "legit.example.com")
	if c := checkTx(t, app, legit).Code; c != CodeOK {
		t.Fatalf("legit tx after spam rejected with code %d", c)
	}
	if res := finalize(t, app, 1, legit); res.TxResults[0].Code != CodeOK {
		t.Fatalf("legit tx after spam failed in block: code %d", res.TxResults[0].Code)
	}
}

// DoS D3: a transaction with a megabyte domain name must fail validation, not
// allocate state.
func TestSTRIDE_DoS_OversizedDomainRejected(t *testing.T) {
	app := newTestApp(t)
	priv, pub := keypair(t)

	// Built by hand: the constructors would refuse to produce this.
	tx := &types.Transaction{
		ChainId: testChainID,
		Body: &types.Transaction_Register{Register: &types.RegisterTx{
			Certificate: &types.Certificate{
				Domain:    strings.Repeat("a", 1_000_000),
				PublicKey: pub,
				Algorithm: types.Algorithm_ALGORITHM_ED25519,
				ValidFrom: testValidFrom,
			},
		}},
	}
	if err := tx.Sign(priv); err != nil {
		t.Fatal(err)
	}

	if c := checkTx(t, app, marshalTx(t, tx)).Code; c != CodeValidation {
		t.Fatalf("oversized domain code = %d, want %d", c, CodeValidation)
	}
}

// DoS variant: an oversized revocation reason is rejected the same way.
func TestSTRIDE_DoS_OversizedReasonRejected(t *testing.T) {
	app := newTestApp(t)
	priv, pub := keypair(t)
	finalize(t, app, 1, signedRegister(t, priv, pub, "example.com"))

	tx := &types.Transaction{
		ChainId: testChainID,
		Body: &types.Transaction_Revoke{Revoke: &types.RevokeTx{
			Domain: "example.com",
			Nonce:  1,
			Reason: strings.Repeat("r", 1_000_000),
		}},
	}
	if err := tx.Sign(priv); err != nil {
		t.Fatal(err)
	}

	if c := checkTx(t, app, marshalTx(t, tx)).Code; c != CodeValidation {
		t.Fatalf("oversized reason code = %d, want %d", c, CodeValidation)
	}
	if queryDomainState(t, app, "example.com").GetRevoked() {
		t.Fatal("oversized revoke mutated state")
	}
}

// Elevation of privilege P2: Mallory tries to rotate Alice's domain onto his
// own key, signing with his own key. The owner key recorded in state must be
// the one that authorizes rotations.
func TestSTRIDE_EoP_UnauthorizedRotateRejected(t *testing.T) {
	app := newTestApp(t)
	alicePriv, alicePub := keypair(t)
	malloryPriv, _ := keypair(t)
	_, malloryNewPub := keypair(t)

	finalize(t, app, 1, signedRegister(t, alicePriv, alicePub, "alice.com"))

	takeover := signedRotate(t, malloryPriv, "alice.com", 1, malloryNewPub)
	if c := checkTx(t, app, takeover).Code; c != CodeSignature {
		t.Fatalf("unauthorized rotate code = %d, want %d", c, CodeSignature)
	}
	res := finalize(t, app, 2, takeover)
	if res.TxResults[0].Code == CodeOK {
		t.Fatal("unauthorized rotate was executed")
	}
	ds := queryDomainState(t, app, "alice.com")
	if !bytes.Equal(ds.GetCertificate().GetPublicKey(), alicePub) {
		t.Fatal("owner key was replaced by an unauthorized rotate")
	}
}

// Elevation of privilege: replaying the original RegisterTx after a revocation
// must not resurrect the certificate. The revoked DomainState stays in the
// tree, so the domain still "exists" and the replay fails the existence check
// — revocation is permanent by construction (an "un-revoke" attack on a
// compromised key is impossible).
func TestSTRIDE_EoP_RevocationIsPermanent(t *testing.T) {
	app := newTestApp(t)
	priv, pub := keypair(t)

	register := signedRegister(t, priv, pub, "example.com")
	finalize(t, app, 1, register)
	if res := finalize(t, app, 2, signedRevoke(t, priv, "example.com", 1, "key compromised")); res.TxResults[0].Code != CodeOK {
		t.Fatalf("revoke failed: code %d", res.TxResults[0].Code)
	}

	// Replay the original, validly signed registration.
	if c := checkTx(t, app, register).Code; c != CodeSemantic {
		t.Fatalf("register replay after revoke code = %d, want %d", c, CodeSemantic)
	}
	res := finalize(t, app, 3, register)
	if res.TxResults[0].Code != CodeSemantic {
		t.Fatalf("register replay executed: code %d", res.TxResults[0].Code)
	}
	if !queryDomainState(t, app, "example.com").GetRevoked() {
		t.Fatal("replayed register un-revoked the domain")
	}
}

// Elevation of privilege: nonces must be consumed in order — a mutation with a
// future nonce never executes, so an attacker cannot "pre-burn" nonces or
// reorder captured transactions. Note the two-stage design (ADR 011): CheckTx
// deliberately tolerates future nonces (a queued tx must not be dropped just
// because its predecessor is still in the mempool); the exact-nonce check that
// matters is FinalizeBlock's.
func TestSTRIDE_EoP_NonceGapRejected(t *testing.T) {
	app := newTestApp(t)
	priv, pub := keypair(t)
	finalize(t, app, 1, signedRegister(t, priv, pub, "example.com"))

	gap := signedRevoke(t, priv, "example.com", 5, "")
	if c := checkTx(t, app, gap).Code; c != CodeOK {
		t.Fatalf("CheckTx future-nonce code = %d, want %d (mempool tolerates queued nonces)", c, CodeOK)
	}
	res := finalize(t, app, 2, gap)
	if res.TxResults[0].Code != CodeSemantic {
		t.Fatalf("nonce-gap revoke executed: code %d", res.TxResults[0].Code)
	}
	if queryDomainState(t, app, "example.com").GetRevoked() {
		t.Fatal("nonce-gap revoke mutated state")
	}
}
