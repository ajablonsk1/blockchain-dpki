package verifier

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ajablonsk1/blockchain-dpki/internal/crypto"
	"github.com/ajablonsk1/blockchain-dpki/internal/types"
)

const testChainID = "test-chain"

// fakeResolver is a TXTResolver returning canned records or an error.
type fakeResolver struct {
	records []string
	err     error
}

func (f fakeResolver) LookupTXT(_ context.Context, _ string) ([]string, error) {
	return f.records, f.err
}

// registerTx builds an (unsigned) RegisterTx; the verifier never inspects the
// signature, only the certificate's domain and key.
func registerTx(t *testing.T, domain string, pub []byte) *types.RegisterTx {
	t.Helper()
	cert, err := types.NewCertificate(domain, pub, types.Algorithm_ALGORITHM_ED25519, 1_700_000_000)
	if err != nil {
		t.Fatalf("NewCertificate: %v", err)
	}
	return &types.RegisterTx{Certificate: cert}
}

func newPub(t *testing.T) []byte {
	t.Helper()
	_, pub, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return pub
}

func TestDNSVerifier_CorrectRecordPasses(t *testing.T) {
	pub := newPub(t)
	want := ChallengeValue("example.com", pub, testChainID)
	v := NewDNSVerifier(fakeResolver{records: []string{"unrelated", want}}, testChainID, time.Second, nil)

	if err := v.Verify(context.Background(), registerTx(t, "example.com", pub)); err != nil {
		t.Fatalf("Verify = %v, want nil", err)
	}
}

func TestDNSVerifier_WrongValueFails(t *testing.T) {
	pub := newPub(t)
	v := NewDNSVerifier(fakeResolver{records: []string{"not-the-challenge"}}, testChainID, time.Second, nil)

	err := v.Verify(context.Background(), registerTx(t, "example.com", pub))
	if !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("Verify = %v, want ErrChallengeNotFound", err)
	}
}

func TestDNSVerifier_NoRecordsFails(t *testing.T) {
	pub := newPub(t)
	v := NewDNSVerifier(fakeResolver{records: nil}, testChainID, time.Second, nil)

	if err := v.Verify(context.Background(), registerTx(t, "example.com", pub)); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("Verify = %v, want ErrChallengeNotFound", err)
	}
}

func TestDNSVerifier_LookupErrorWrapped(t *testing.T) {
	pub := newPub(t)
	v := NewDNSVerifier(fakeResolver{err: errors.New("server misbehaving")}, testChainID, time.Second, nil)

	if err := v.Verify(context.Background(), registerTx(t, "example.com", pub)); !errors.Is(err, ErrDNSLookup) {
		t.Fatalf("Verify = %v, want ErrDNSLookup", err)
	}
}

func TestDNSVerifier_NilTx(t *testing.T) {
	v := NewDNSVerifier(fakeResolver{}, testChainID, time.Second, nil)
	if err := v.Verify(context.Background(), nil); !errors.Is(err, ErrNilRegisterTx) {
		t.Fatalf("Verify(nil) = %v, want ErrNilRegisterTx", err)
	}
}

// TestDNSVerifier_FrontRunningRejected models the front-running attack: the real
// owner publishes a challenge bound to THEIR key; an attacker who copies the
// registration but swaps in their own key computes a different expected value,
// so the published record does not match and their verification fails.
func TestDNSVerifier_FrontRunningRejected(t *testing.T) {
	ownerPub := newPub(t)
	attackerPub := newPub(t)

	published := ChallengeValue("example.com", ownerPub, testChainID)
	v := NewDNSVerifier(fakeResolver{records: []string{published}}, testChainID, time.Second, nil)

	if err := v.Verify(context.Background(), registerTx(t, "example.com", ownerPub)); err != nil {
		t.Fatalf("owner Verify = %v, want nil", err)
	}
	if err := v.Verify(context.Background(), registerTx(t, "example.com", attackerPub)); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("attacker Verify = %v, want ErrChallengeNotFound", err)
	}
}
