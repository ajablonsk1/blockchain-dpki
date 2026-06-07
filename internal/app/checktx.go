package app

import (
	"context"

	abci "github.com/cometbft/cometbft/abci/types"

	"github.com/ajablonsk1/blockchain-dpki/internal/types"
)

// CheckTx is the cheap mempool gate: it decides whether a transaction is a
// plausible candidate for a block without mutating state. It runs the syntactic
// validation, checks the chain ID, verifies the signature, and does a light
// semantic check (does the domain exist when it must, is the nonce not already
// stale). The authoritative, exact-nonce semantic check happens in
// FinalizeBlock, because the mempool may hold transactions slightly out of order.
func (app *App) CheckTx(ctx context.Context, req *abci.RequestCheckTx) (*abci.ResponseCheckTx, error) {
	tx, err := decodeTransaction(req.Tx)
	if err != nil {
		return checkErr(CodeDecode, "%v", err), nil
	}
	if err := tx.Validate(); err != nil {
		return checkErr(CodeValidation, "%v", err), nil
	}
	if tx.GetChainId() != app.chainID {
		return checkErr(CodeChainID, "wrong chain id: got %q want %q", tx.GetChainId(), app.chainID), nil
	}

	// State-dependent checks under the read lock.
	app.mu.RLock()
	_, sigErr := app.verifySignature(tx)
	var semErr error
	if sigErr == nil {
		semErr = app.lightSemanticCheck(tx)
	}
	app.mu.RUnlock()

	if sigErr != nil {
		return checkErr(CodeSignature, "%v", sigErr), nil
	}
	if semErr != nil {
		return checkErr(CodeSemantic, "%v", semErr), nil
	}

	// Domain-ownership verification for registrations. This is a DNS lookup —
	// non-deterministic external I/O — so it runs OUTSIDE the state lock and is a
	// pre-consensus admission gate only, never part of FinalizeBlock.
	if reg := tx.GetRegister(); reg != nil {
		if err := app.verifier.Verify(ctx, reg); err != nil {
			return checkErr(CodeVerification, "%v", err), nil
		}
	}

	return checkOK(), nil
}

// lightSemanticCheck rejects transactions that cannot possibly become valid:
// registering a domain that already exists, or mutating a domain with a nonce
// that is already in the past. It deliberately does not enforce the exact next
// nonce so that a transaction queued ahead of its predecessor is not dropped
// from the mempool.
func (app *App) lightSemanticCheck(tx *types.Transaction) error {
	switch body := tx.GetBody().(type) {
	case *types.Transaction_Register:
		_, present, err := app.smt.GetDomain(body.Register.GetCertificate().GetDomain())
		if err != nil {
			return err
		}
		if present {
			return errDomainExists
		}
		return nil

	case *types.Transaction_Revoke:
		return app.checkMutableNonce(body.Revoke.GetDomain(), body.Revoke.GetNonce())

	case *types.Transaction_Rotate:
		return app.checkMutableNonce(body.Rotate.GetDomain(), body.Rotate.GetNonce())

	default:
		return errUnknownTxType
	}
}

// checkMutableNonce verifies that a domain exists, is not revoked, and that the
// supplied nonce is not stale (strictly greater than the stored nonce).
func (app *App) checkMutableNonce(domain string, nonce uint64) error {
	ds, present, err := app.smt.GetDomain(domain)
	if err != nil {
		return err
	}
	if !present {
		return errDomainNotFound
	}
	if ds.GetRevoked() {
		return errDomainRevoked
	}
	if nonce <= ds.GetNonce() {
		return errStaleNonce
	}
	return nil
}
