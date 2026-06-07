package app

import (
	"context"

	abci "github.com/cometbft/cometbft/abci/types"
	cmtcrypto "github.com/cometbft/cometbft/proto/tendermint/crypto"
	"google.golang.org/protobuf/proto"

	"github.com/ajablonsk1/blockchain-dpki/internal/state"
)

// Query paths exposed by the application. Path "/domain" returns the current
// DomainState for a domain; "/domain/proof" additionally returns a Merkle proof
// that a light client can verify offline against the committed app hash.
const (
	QueryPathDomain      = "/domain"
	QueryPathDomainProof = "/domain/proof"

	// ProofOpType labels the proof carried in ResponseQuery.ProofOps so a client
	// knows to decode it with state.Proof.UnmarshalBinary and verify it with
	// state.VerifyDomainProof.
	ProofOpType = "dpki:smt"
)

// Query reads committed state. req.Data carries the domain name. A query against
// an absent domain is not an error: it returns Code 0 with an empty value (and,
// for the proof path, a verifiable non-inclusion proof).
func (app *App) Query(_ context.Context, req *abci.RequestQuery) (*abci.ResponseQuery, error) {
	app.mu.RLock()
	defer app.mu.RUnlock()

	switch req.Path {
	case QueryPathDomain:
		return app.queryDomain(req.Data)
	case QueryPathDomainProof:
		return app.queryDomainProof(req.Data)
	default:
		return &abci.ResponseQuery{Code: CodeUnknownQuery, Log: "unknown query path: " + req.Path}, nil
	}
}

// queryDomain returns the marshaled DomainState, or an empty value if the domain
// is not registered.
func (app *App) queryDomain(data []byte) (*abci.ResponseQuery, error) {
	domain := string(data)

	ds, present, err := app.smt.GetDomain(domain)
	if err != nil {
		return &abci.ResponseQuery{Code: CodeInternal, Log: err.Error()}, nil
	}

	resp := &abci.ResponseQuery{Code: CodeOK, Key: data, Height: app.height}
	if !present {
		resp.Log = "domain not found"
		return resp, nil
	}

	value, err := proto.Marshal(ds)
	if err != nil {
		return &abci.ResponseQuery{Code: CodeInternal, Log: err.Error()}, nil
	}
	resp.Value = value
	return resp, nil
}

// queryDomainProof returns the DomainState together with a compressed Merkle
// proof. For a registered domain the proof is an inclusion proof and Value holds
// the marshaled state; for an absent domain it is a non-inclusion proof and
// Value is empty. Either way the proof verifies against the app hash at Height.
func (app *App) queryDomainProof(data []byte) (*abci.ResponseQuery, error) {
	domain := string(data)

	ds, present, err := app.smt.GetDomain(domain)
	if err != nil {
		return &abci.ResponseQuery{Code: CodeInternal, Log: err.Error()}, nil
	}

	proof, err := app.smt.ProveDomain(domain)
	if err != nil {
		return &abci.ResponseQuery{Code: CodeInternal, Log: err.Error()}, nil
	}
	proofBytes, err := proof.MarshalBinary()
	if err != nil {
		return &abci.ResponseQuery{Code: CodeInternal, Log: err.Error()}, nil
	}

	resp := &abci.ResponseQuery{
		Code:   CodeOK,
		Key:    data,
		Height: app.height,
		ProofOps: &cmtcrypto.ProofOps{
			Ops: []cmtcrypto.ProofOp{{
				Type: ProofOpType,
				Key:  state.DomainKey(domain),
				Data: proofBytes,
			}},
		},
	}
	if !present {
		resp.Log = "domain not found"
		return resp, nil
	}

	value, err := proto.Marshal(ds)
	if err != nil {
		return &abci.ResponseQuery{Code: CodeInternal, Log: err.Error()}, nil
	}
	resp.Value = value
	return resp, nil
}
