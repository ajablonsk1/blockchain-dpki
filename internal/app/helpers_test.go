package app

import (
	"context"
	"testing"
	"time"

	abci "github.com/cometbft/cometbft/abci/types"
	"google.golang.org/protobuf/proto"

	"github.com/ajablonsk1/blockchain-dpki/internal/crypto"
	"github.com/ajablonsk1/blockchain-dpki/internal/state"
	"github.com/ajablonsk1/blockchain-dpki/internal/types"
)

const (
	testChainID   = "test-chain"
	testValidFrom = int64(1_700_000_000) // 2023-11-14, > MinValidTimestamp
)

// testBlockTime is the deterministic block timestamp used by the test harness.
var testBlockTime = time.Unix(testValidFrom, 0).UTC()

func newTestApp(t *testing.T) *App {
	t.Helper()
	return NewApp(state.NewSMT(state.NewMemoryStore()), testChainID, nil)
}

// keypair returns a fresh Ed25519 key pair.
func keypair(t *testing.T) (priv, pub []byte) {
	t.Helper()
	priv, pub, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair: %v", err)
	}
	return priv, pub
}

// marshalTx serializes a transaction to its wire bytes.
func marshalTx(t *testing.T, tx *types.Transaction) []byte {
	t.Helper()
	raw, err := proto.Marshal(tx)
	if err != nil {
		t.Fatalf("marshal tx: %v", err)
	}
	return raw
}

// signedRegister builds and signs a RegisterTx for domain using pub as the
// certificate key and priv as the signer.
func signedRegister(t *testing.T, priv, pub []byte, domain string) []byte {
	t.Helper()
	cert, err := types.NewCertificate(domain, pub, types.Algorithm_ALGORITHM_ED25519, testValidFrom)
	if err != nil {
		t.Fatalf("NewCertificate: %v", err)
	}
	tx, err := types.NewRegisterTx(cert, testChainID)
	if err != nil {
		t.Fatalf("NewRegisterTx: %v", err)
	}
	if err := tx.Sign(priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return marshalTx(t, tx)
}

func signedRevoke(t *testing.T, priv []byte, domain string, nonce uint64, reason string) []byte {
	t.Helper()
	tx, err := types.NewRevokeTx(domain, nonce, reason, testChainID)
	if err != nil {
		t.Fatalf("NewRevokeTx: %v", err)
	}
	if err := tx.Sign(priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return marshalTx(t, tx)
}

func signedRotate(t *testing.T, priv []byte, domain string, nonce uint64, newPub []byte) []byte {
	t.Helper()
	tx, err := types.NewRotateTx(domain, nonce, newPub, types.Algorithm_ALGORITHM_ED25519, testChainID)
	if err != nil {
		t.Fatalf("NewRotateTx: %v", err)
	}
	if err := tx.Sign(priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return marshalTx(t, tx)
}

// finalize runs FinalizeBlock + Commit for one block at the given height and
// returns the response.
func finalize(t *testing.T, app *App, height int64, txs ...[]byte) *abci.ResponseFinalizeBlock {
	t.Helper()
	res, err := app.FinalizeBlock(context.Background(), &abci.RequestFinalizeBlock{
		Txs:    txs,
		Height: height,
		Time:   testBlockTime,
	})
	if err != nil {
		t.Fatalf("FinalizeBlock: %v", err)
	}
	if _, err := app.Commit(context.Background(), &abci.RequestCommit{}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return res
}

// checkTx runs CheckTx and returns the response.
func checkTx(t *testing.T, app *App, raw []byte) *abci.ResponseCheckTx {
	t.Helper()
	res, err := app.CheckTx(context.Background(), &abci.RequestCheckTx{Tx: raw})
	if err != nil {
		t.Fatalf("CheckTx: %v", err)
	}
	return res
}

// queryDomainState runs the /domain query and returns the decoded state (nil if
// absent).
func queryDomainState(t *testing.T, app *App, domain string) *types.DomainState {
	t.Helper()
	res, err := app.Query(context.Background(), &abci.RequestQuery{Path: QueryPathDomain, Data: []byte(domain)})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if res.Code != CodeOK {
		t.Fatalf("Query code = %d, log = %q", res.Code, res.Log)
	}
	if len(res.Value) == 0 {
		return nil
	}
	ds := &types.DomainState{}
	if err := proto.Unmarshal(res.Value, ds); err != nil {
		t.Fatalf("unmarshal domain state: %v", err)
	}
	return ds
}
