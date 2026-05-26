// Package testhelpers provides reusable test fixtures for the dpki module.
package testhelpers

import (
	"testing"

	"github.com/ajablonsk1/blockchain-dpki/internal/crypto"
	"github.com/ajablonsk1/blockchain-dpki/internal/types"
)

// MustGenerateKeyPair generates an Ed25519 key pair or calls t.Fatal.
func MustGenerateKeyPair(t *testing.T) (priv, pub []byte) {
	t.Helper()
	priv, pub, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("MustGenerateKeyPair: %v", err)
	}
	return priv, pub
}

// MustNewCertificate creates a valid Certificate for domain or calls t.Fatal.
func MustNewCertificate(t *testing.T, domain string, pub []byte) *types.Certificate {
	t.Helper()
	cert, err := types.NewCertificate(domain, pub, types.Algorithm_ALGORITHM_ED25519, types.MinValidTimestamp)
	if err != nil {
		t.Fatalf("MustNewCertificate(%q): %v", domain, err)
	}
	return cert
}

// MustNewSignedRegisterTx builds a RegisterTx for domain, signs it, and
// returns the transaction together with the private key used for signing.
// The public key can be retrieved from tx.GetRegister().GetCertificate().GetPublicKey().
func MustNewSignedRegisterTx(t *testing.T, domain string) (*types.Transaction, []byte) {
	t.Helper()
	priv, pub := MustGenerateKeyPair(t)
	cert := MustNewCertificate(t, domain, pub)

	tx, err := types.NewRegisterTx(cert, "testchain")
	if err != nil {
		t.Fatalf("MustNewSignedRegisterTx NewRegisterTx: %v", err)
	}

	if err := tx.Sign(priv); err != nil {
		t.Fatalf("MustNewSignedRegisterTx Sign: %v", err)
	}

	return tx, priv
}

// MustNewSignedRevokeTx builds a RevokeTx for domain, signs it, and returns
// the transaction together with the private key used for signing.
func MustNewSignedRevokeTx(t *testing.T, domain string, nonce uint64, priv, pub []byte) *types.Transaction {
	t.Helper()
	tx, err := types.NewRevokeTx(domain, nonce, "", "testchain")
	if err != nil {
		t.Fatalf("MustNewSignedRevokeTx NewRevokeTx: %v", err)
	}

	if err := tx.Sign(priv); err != nil {
		t.Fatalf("MustNewSignedRevokeTx Sign: %v", err)
	}

	return tx
}

// MustNewSignedRotateTx builds a RotateTx rotating domain to newPub, signed
// by currentPriv (the current owner's key).
func MustNewSignedRotateTx(t *testing.T, domain string, nonce uint64, currentPriv, newPub []byte) *types.Transaction {
	t.Helper()
	tx, err := types.NewRotateTx(domain, nonce, newPub, types.Algorithm_ALGORITHM_ED25519, "testchain")
	if err != nil {
		t.Fatalf("MustNewSignedRotateTx NewRotateTx: %v", err)
	}

	if err := tx.Sign(currentPriv); err != nil {
		t.Fatalf("MustNewSignedRotateTx Sign: %v", err)
	}

	return tx
}
