package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	merkle "local/merkle-trees"

	abcitypes "github.com/cometbft/cometbft/abci/types"
)

type PKIApplication struct {
	pkiState      *PKIState
	tree          *merkle.MerkleTree
	sortedDomains []string
}

type PKIState struct {
	Certs map[string]*CertEntry
}

type CertEntry struct {
	Domain    string
	PubKey    []byte
	CreatedAt int64
	Revoked   bool
	RevokedAt int64
	ExpiresAt int64
}

var _ abcitypes.Application = (*PKIApplication)(nil)

func NewPKIApplication() *PKIApplication {
	return &PKIApplication{&PKIState{make(map[string]*CertEntry)}, merkle.NewTree([][]byte{}), []string{}}
}

func (app *PKIApplication) Info(_ context.Context, info *abcitypes.RequestInfo) (*abcitypes.ResponseInfo, error) {
	return &abcitypes.ResponseInfo{}, nil
}

func (app *PKIApplication) Query(_ context.Context, req *abcitypes.RequestQuery) (*abcitypes.ResponseQuery, error) {
	domain := string(req.Data)
	i, exists := slices.BinarySearch(app.sortedDomains, domain)
	if !exists {
		return &abcitypes.ResponseQuery{Code: 1, Log: "domain not found"}, nil
	}

	proof, err := app.tree.Proof(i)
	if err != nil {
		return &abcitypes.ResponseQuery{Code: 2, Log: "error creating proof"}, nil
	}
	certEntry := app.pkiState.Certs[domain]

	responseJson, err := json.Marshal(struct {
		CertEntry *CertEntry
		Proof     []merkle.ProofElement
		RootHash  []byte
		Index     int
	}{certEntry, proof, app.tree.RootHash(), i})
	if err != nil {
		return &abcitypes.ResponseQuery{Code: 3, Log: "error marshaling cert entry"}, nil
	}
	return &abcitypes.ResponseQuery{Code: 0, Value: responseJson}, nil
}

func (app *PKIApplication) CheckTx(_ context.Context, check *abcitypes.RequestCheckTx) (*abcitypes.ResponseCheckTx, error) {
	code := app.isTxValid(check.Tx)
	return &abcitypes.ResponseCheckTx{Code: code}, nil
}

func (app *PKIApplication) signatureValid(pubKeyBytes, message, signature []byte) bool {
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return false
	}

	if len(signature) != ed25519.SignatureSize {
		return false
	}

	return ed25519.Verify(ed25519.PublicKey(pubKeyBytes), message, signature)
}

func (app *PKIApplication) isTxValid(tx []byte) uint32 {
	parts := bytes.Split(tx, []byte("|"))
	if len(parts) < 2 {
		return 1
	}

	command := string(parts[0])
	switch command {
	case "REGISTER":
		if len(parts) != 5 {
			return 1
		}

		domain, pubKeyHex, signHex, ttlBytes := parts[1], parts[2], parts[3], parts[4]

		_, exist := app.pkiState.Certs[string(domain)]
		if exist {
			return 1
		}

		pubKey, err := hex.DecodeString(string(pubKeyHex))
		if err != nil {
			return 1
		}

		signature, err := hex.DecodeString(string(signHex))
		if err != nil {
			return 1
		}

		if !app.signatureValid(pubKey, domain, signature) {
			return 1
		}

		_, err = strconv.Atoi(string(ttlBytes))
		if err != nil {
			return 1
		}

	case "REVOKE":
		if len(parts) != 3 {
			return 1
		}

		domain, signHex := parts[1], parts[2]

		certEntry, exist := app.pkiState.Certs[string(domain)]
		if !exist {
			return 1
		}

		signature, err := hex.DecodeString(string(signHex))
		if err != nil {
			return 1
		}

		if certEntry.Revoked {
			return 1
		}

		if !app.signatureValid(certEntry.PubKey, domain, signature) {
			return 1
		}
	default:
		return 1
	}

	return 0
}

func (app *PKIApplication) InitChain(_ context.Context, chain *abcitypes.RequestInitChain) (*abcitypes.ResponseInitChain, error) {
	return &abcitypes.ResponseInitChain{}, nil
}

func (app *PKIApplication) PrepareProposal(_ context.Context, proposal *abcitypes.RequestPrepareProposal) (*abcitypes.ResponsePrepareProposal, error) {
	return &abcitypes.ResponsePrepareProposal{Txs: proposal.Txs}, nil
}

func (app *PKIApplication) ProcessProposal(_ context.Context, proposal *abcitypes.RequestProcessProposal) (*abcitypes.ResponseProcessProposal, error) {
	return &abcitypes.ResponseProcessProposal{Status: abcitypes.ResponseProcessProposal_ACCEPT}, nil
}

func (app *PKIApplication) FinalizeBlock(_ context.Context, req *abcitypes.RequestFinalizeBlock) (*abcitypes.ResponseFinalizeBlock, error) {
	txs := make([]*abcitypes.ExecTxResult, len(req.Txs))

	for i, tx := range req.Txs {
		code := app.isTxValid(tx)
		if code != 0 {
			txs[i] = &abcitypes.ExecTxResult{Code: code}
			continue
		}
		parts := bytes.Split(tx, []byte("|"))
		command := string(parts[0])
		domain := string(parts[1])

		switch command {
		case "REGISTER":
			pubKeyHex := parts[2]
			pubKey, _ := hex.DecodeString(string(pubKeyHex))
			ttl, _ := strconv.Atoi(string(parts[4]))

			certEntry := &CertEntry{
				Domain:    string(domain),
				PubKey:    pubKey,
				CreatedAt: req.Time.Unix(),
				ExpiresAt: req.Time.Unix() + int64(ttl),
			}
			certs := app.pkiState.Certs
			certs[domain] = certEntry

		case "REVOKE":
			if req.Time.Unix() > app.pkiState.Certs[domain].ExpiresAt {
				txs[i] = &abcitypes.ExecTxResult{Code: 2}
				continue
			}
			app.pkiState.Certs[domain].Revoked = true
			app.pkiState.Certs[domain].RevokedAt = req.Time.Unix()
		}

		txs[i] = &abcitypes.ExecTxResult{Code: 0}
	}

	return &abcitypes.ResponseFinalizeBlock{TxResults: txs}, nil
}

func (app *PKIApplication) Commit(_ context.Context, commit *abcitypes.RequestCommit) (*abcitypes.ResponseCommit, error) {
	certs := app.pkiState.Certs
	certEntires := make([]*CertEntry, 0, len(certs))
	for _, certEntry := range certs {
		certEntires = append(certEntires, certEntry)
	}

	slices.SortFunc(certEntires, func(a, b *CertEntry) int {
		return strings.Compare(a.Domain, b.Domain)
	})

	sortedDomains := make([]string, len(certEntires))
	certEntriesByte := make([][]byte, len(certEntires))
	for i, certEntry := range certEntires {
		sortedDomains[i] = certEntry.Domain
		certEntryBytes, err := json.Marshal(certEntry)
		if err != nil {
			return nil, fmt.Errorf("error marshaling cert entry: %w", err)
		}
		certEntriesByte[i] = certEntryBytes
	}

	app.sortedDomains = sortedDomains
	app.tree = merkle.NewTree(certEntriesByte)

	return &abcitypes.ResponseCommit{}, nil
}

func (app *PKIApplication) ListSnapshots(_ context.Context, snapshots *abcitypes.RequestListSnapshots) (*abcitypes.ResponseListSnapshots, error) {
	return &abcitypes.ResponseListSnapshots{}, nil
}

func (app *PKIApplication) OfferSnapshot(_ context.Context, snapshot *abcitypes.RequestOfferSnapshot) (*abcitypes.ResponseOfferSnapshot, error) {
	return &abcitypes.ResponseOfferSnapshot{}, nil
}

func (app *PKIApplication) LoadSnapshotChunk(_ context.Context, chunk *abcitypes.RequestLoadSnapshotChunk) (*abcitypes.ResponseLoadSnapshotChunk, error) {
	return &abcitypes.ResponseLoadSnapshotChunk{}, nil
}

func (app *PKIApplication) ApplySnapshotChunk(_ context.Context, chunk *abcitypes.RequestApplySnapshotChunk) (*abcitypes.ResponseApplySnapshotChunk, error) {
	return &abcitypes.ResponseApplySnapshotChunk{Result: abcitypes.ResponseApplySnapshotChunk_ACCEPT}, nil
}

func (app *PKIApplication) ExtendVote(_ context.Context, extend *abcitypes.RequestExtendVote) (*abcitypes.ResponseExtendVote, error) {
	return &abcitypes.ResponseExtendVote{}, nil
}

func (app *PKIApplication) VerifyVoteExtension(_ context.Context, verify *abcitypes.RequestVerifyVoteExtension) (*abcitypes.ResponseVerifyVoteExtension, error) {
	return &abcitypes.ResponseVerifyVoteExtension{}, nil
}
