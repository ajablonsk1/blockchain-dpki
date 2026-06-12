package main

import (
	"fmt"
	"time"

	"github.com/ajablonsk1/blockchain-dpki/internal/crypto"
	"github.com/ajablonsk1/blockchain-dpki/internal/types"
)

// txFactory builds signed RegisterTx with unique domains. One keypair signs
// everything: key generation is not the system under test, and the app accepts
// any number of domains per key.
type txFactory struct {
	priv    []byte
	pub     []byte
	chainID string
	prefix  string
}

func newTxFactory(chainID string) (*txFactory, error) {
	priv, pub, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		return nil, err
	}
	return &txFactory{
		priv:    priv,
		pub:     pub,
		chainID: chainID,
		// The timestamp keeps domains unique across benchmark invocations
		// against the same chain.
		prefix: fmt.Sprintf("bench-%d", time.Now().UnixNano()),
	}, nil
}

func (f *txFactory) register(seq int) (*types.Transaction, error) {
	domain := fmt.Sprintf("%s-%d.example.com", f.prefix, seq)
	cert, err := types.NewCertificate(domain, f.pub, types.Algorithm_ALGORITHM_ED25519, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	tx, err := types.NewRegisterTx(cert, f.chainID)
	if err != nil {
		return nil, err
	}
	if err := tx.Sign(f.priv); err != nil {
		return nil, err
	}
	return tx, nil
}
