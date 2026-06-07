package app

import (
	"context"
	"errors"
	"testing"

	abci "github.com/cometbft/cometbft/abci/types"

	"github.com/ajablonsk1/blockchain-dpki/internal/verifier"
)

// appResolver is a verifier.TXTResolver returning a fixed record set, used to
// drive a real DNSVerifier from the app tests.
type appResolver struct{ records map[string][]string }

func (r appResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	return r.records[name], nil
}

func processProposal(t *testing.T, app *App, txs ...[]byte) abci.ResponseProcessProposal_ProposalStatus {
	t.Helper()
	res, err := app.ProcessProposal(context.Background(), &abci.RequestProcessProposal{Txs: txs})
	if err != nil {
		t.Fatalf("ProcessProposal: %v", err)
	}
	return res.Status
}

// TestCheckTx_RejectsUnverifiedRegister: a registration whose domain ownership
// cannot be verified is rejected at the mempool gate.
func TestCheckTx_RejectsUnverifiedRegister(t *testing.T) {
	app := newTestAppWithVerifier(t, &verifier.MockVerifier{Allowed: map[string]bool{"ok.com": true}})
	priv, pub := keypair(t)

	if c := checkTx(t, app, signedRegister(t, priv, pub, "ok.com")).Code; c != CodeOK {
		t.Fatalf("verified register code = %d, want %d", c, CodeOK)
	}
	if c := checkTx(t, app, signedRegister(t, priv, pub, "blocked.com")).Code; c != CodeVerification {
		t.Fatalf("unverified register code = %d, want %d", c, CodeVerification)
	}
}

// TestCheckTx_VerifierSkippedForMutations: revoke/rotate must not trigger domain
// verification. A verifier that always errors must not block a revoke of an
// already-registered domain.
func TestCheckTx_VerifierSkippedForMutations(t *testing.T) {
	app := newTestAppWithVerifier(t, &verifier.MockVerifier{Err: errors.New("verifier must not be called")})
	priv, pub := keypair(t)

	// Seed the domain via FinalizeBlock, which does not verify.
	finalize(t, app, 1, signedRegister(t, priv, pub, "example.com"))

	if c := checkTx(t, app, signedRevoke(t, priv, "example.com", 1, "")).Code; c != CodeOK {
		t.Fatalf("revoke CheckTx code = %d, want %d (verifier should be skipped)", c, CodeOK)
	}
}

// TestFinalizeBlock_DoesNotVerify is the replay-safety guarantee: FinalizeBlock
// applies a registration even when the verifier would reject it, because
// verification is a pre-consensus gate and must not be part of the deterministic
// state machine. Otherwise replaying history after the DNS record is gone would
// diverge.
func TestFinalizeBlock_DoesNotVerify(t *testing.T) {
	app := newTestAppWithVerifier(t, &verifier.MockVerifier{Err: errors.New("would reject")})
	priv, pub := keypair(t)

	res := finalize(t, app, 1, signedRegister(t, priv, pub, "example.com"))
	if res.TxResults[0].Code != CodeOK {
		t.Fatalf("FinalizeBlock register code = %d, want %d", res.TxResults[0].Code, CodeOK)
	}
	if queryDomainState(t, app, "example.com") == nil {
		t.Fatal("register not applied by FinalizeBlock")
	}
}

// TestProcessProposal_RejectsUnverifiedRegister: the consensus gate rejects a
// whole block that contains an unverifiable registration.
func TestProcessProposal_RejectsUnverifiedRegister(t *testing.T) {
	app := newTestAppWithVerifier(t, &verifier.MockVerifier{Allowed: map[string]bool{"ok.com": true}})
	priv, pub := keypair(t)

	if s := processProposal(t, app, signedRegister(t, priv, pub, "ok.com")); s != abci.ResponseProcessProposal_ACCEPT {
		t.Fatalf("verified proposal status = %v, want ACCEPT", s)
	}
	if s := processProposal(t, app, signedRegister(t, priv, pub, "blocked.com")); s != abci.ResponseProcessProposal_REJECT {
		t.Fatalf("unverified proposal status = %v, want REJECT", s)
	}
}

// TestProcessProposal_IgnoresNonRegister: non-register transactions are not
// subject to domain verification, so a proposal of a revoke is accepted even
// with a failing verifier.
func TestProcessProposal_IgnoresNonRegister(t *testing.T) {
	app := newTestAppWithVerifier(t, &verifier.MockVerifier{Err: errors.New("must not be called")})
	priv, _ := keypair(t)

	revoke := signedRevoke(t, priv, "example.com", 1, "")
	if s := processProposal(t, app, revoke); s != abci.ResponseProcessProposal_ACCEPT {
		t.Fatalf("revoke proposal status = %v, want ACCEPT", s)
	}
	// Garbage is left for FinalizeBlock to record, not rejected here.
	if s := processProposal(t, app, []byte("garbage")); s != abci.ResponseProcessProposal_ACCEPT {
		t.Fatalf("garbage proposal status = %v, want ACCEPT", s)
	}
}

// TestFrontRunning_AppLevel drives a real DNSVerifier (over a fake resolver) end
// to end through CheckTx: the owner published a key-bound challenge, so the
// owner's registration is admitted but a front-runner's — same domain, different
// key — is rejected because their expected challenge differs.
func TestFrontRunning_AppLevel(t *testing.T) {
	ownerPriv, ownerPub := keypair(t)
	attackerPriv, attackerPub := keypair(t)
	const domain = "example.com"

	published := verifier.ChallengeValue(domain, ownerPub, testChainID)
	resolver := appResolver{records: map[string][]string{
		verifier.ChallengeName(domain): {published},
	}}
	v := verifier.NewDNSVerifier(resolver, testChainID, 0, nil)
	app := newTestAppWithVerifier(t, v)

	if c := checkTx(t, app, signedRegister(t, ownerPriv, ownerPub, domain)).Code; c != CodeOK {
		t.Fatalf("owner register code = %d, want %d", c, CodeOK)
	}
	if c := checkTx(t, app, signedRegister(t, attackerPriv, attackerPub, domain)).Code; c != CodeVerification {
		t.Fatalf("front-runner register code = %d, want %d", c, CodeVerification)
	}
}
