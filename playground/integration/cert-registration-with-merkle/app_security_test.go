package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/cometbft/cometbft/abci/types"
)

func TestDoubleRegistration(t *testing.T) {
	app := NewPKIApplication()
	tx, _ := buildRegisterTx("test.com", "3600")
	_, err := app.FinalizeBlock(context.TODO(), &types.RequestFinalizeBlock{Txs: [][]byte{tx}})
	if err != nil {
		t.Errorf("error during first domain registration: %v", err)
	}
	app.Commit(context.TODO(), &types.RequestCommit{})

	res, err := app.FinalizeBlock(context.TODO(), &types.RequestFinalizeBlock{Txs: [][]byte{tx}})
	if err != nil {
		t.Errorf("error during second domain registration: %v", err)
	}

	if res.TxResults[0].Code != 1 {
		t.Errorf("expected code 1, got %d", res.TxResults[0].Code)
	}
}

func TestRevokeWithWrongKey(t *testing.T) {
	app := NewPKIApplication()
	tx, _ := buildRegisterTx("test.com", "3600")
	_, err := app.FinalizeBlock(context.TODO(), &types.RequestFinalizeBlock{Txs: [][]byte{tx}})
	if err != nil {
		t.Fatalf("error during domain registration: %v", err)
	}
	app.Commit(context.TODO(), &types.RequestCommit{})

	tx, _ = buildRevokeTxWithNewKey("test.com")
	res, err := app.FinalizeBlock(context.TODO(), &types.RequestFinalizeBlock{Txs: [][]byte{tx}})
	if err != nil {
		t.Errorf("error during domain revoking: %v", err)
	}

	if res.TxResults[0].Code != 1 {
		t.Errorf("expected code 1, got %d", res.TxResults[0].Code)
	}
}

func TestCertificateTampering(t *testing.T) {
	app := NewPKIApplication()
	domain := "test.com"
	tx, _ := buildRegisterTx(domain, "3600")
	_, err := app.FinalizeBlock(context.TODO(), &types.RequestFinalizeBlock{Txs: [][]byte{tx}})
	if err != nil {
		t.Fatalf("error during domain registration: %v", err)
	}
	app.Commit(context.TODO(), &types.RequestCommit{})
	originalRoot := app.tree.RootHash()

	cert := app.pkiState.Certs[domain]
	cert.PubKey = getNewPubKeyBytes()

	app.Commit(context.TODO(), &types.RequestCommit{})
	tamperedRoot := app.tree.RootHash()

	if bytes.Equal(originalRoot, tamperedRoot) {
		t.Error("root hash should change after tampering")
	}
}

func TestExpiredCertificate(t *testing.T) {
	app := NewPKIApplication()
	domain := "test.com"
	tx, privateKey := buildRegisterTx(domain, "1")
	_, err := app.FinalizeBlock(context.TODO(), &types.RequestFinalizeBlock{Txs: [][]byte{tx}, Time: time.Now()})
	if err != nil {
		t.Fatalf("error during domain registration: %v", err)
	}

	revokeTx := buildRevokeTxWithExistingKey("test.com", privateKey)
	res, _ := app.FinalizeBlock(context.TODO(), &types.RequestFinalizeBlock{
		Txs:  [][]byte{revokeTx},
		Time: time.Now().Add(2 * time.Hour),
	})

	if res.TxResults[0].Code != 2 {
		t.Errorf("expected code 2 for expired cert, got %d", res.TxResults[0].Code)
	}
}

func buildRegisterTx(domain string, ttl string) ([]byte, ed25519.PrivateKey) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig := ed25519.Sign(priv, []byte(domain))
	tx := fmt.Sprintf("REGISTER|%s|%s|%s|%s", domain, hex.EncodeToString(pub), hex.EncodeToString(sig), ttl)
	return []byte(tx), priv
}

func buildRevokeTxWithNewKey(domain string) ([]byte, ed25519.PrivateKey) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig := ed25519.Sign(priv, []byte(domain))
	tx := fmt.Sprintf("REVOKE|%s|%s", domain, hex.EncodeToString(sig))
	return []byte(tx), priv
}

func buildRevokeTxWithExistingKey(domain string, privateKey ed25519.PrivateKey) []byte {
	sig := ed25519.Sign(privateKey, []byte(domain))
	tx := fmt.Sprintf("REVOKE|%s|%s", domain, hex.EncodeToString(sig))
	return []byte(tx)
}

func getNewPubKeyBytes() []byte {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	return []byte(pub)
}
