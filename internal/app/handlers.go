package app

import (
	"time"

	abci "github.com/cometbft/cometbft/abci/types"

	"github.com/ajablonsk1/blockchain-dpki/internal/types"
)

// handleRegister binds a domain to a fresh certificate. The signature has
// already been verified against the certificate's own key. It must not already
// exist; the new state starts at nonce 0 (no mutations yet) and unrevoked.
func (app *App) handleRegister(tx *types.RegisterTx, _ time.Time) *abci.ExecTxResult {
	domain := tx.GetCertificate().GetDomain()

	_, present, err := app.smt.GetDomain(domain)
	if err != nil {
		return execErr(CodeInternal, "state read: %v", err)
	}
	if present {
		return execErr(CodeSemantic, "%v", errDomainExists)
	}

	ds := &types.DomainState{
		Certificate: tx.GetCertificate(),
		Nonce:       0,
		Revoked:     false,
	}
	if err := app.smt.SetDomain(domain, ds); err != nil {
		return execErr(CodeInternal, "state write: %v", err)
	}

	app.logger.Info("domain registered", "domain", domain)
	return execOK(domainEvent("register", domain))
}

// handleRevoke marks a domain's binding as revoked. ds is the current state
// looked up during signature verification. The nonce must be exactly the next
// expected value, and a domain cannot be revoked twice.
func (app *App) handleRevoke(tx *types.RevokeTx, ds *types.DomainState, blockTime time.Time) *abci.ExecTxResult {
	domain := tx.GetDomain()

	if ds.GetRevoked() {
		return execErr(CodeSemantic, "%v", errDomainRevoked)
	}
	if tx.GetNonce() != expectedNonce(ds) {
		return execErr(CodeSemantic, "%v: got %d want %d", errBadNonce, tx.GetNonce(), expectedNonce(ds))
	}

	ds.Revoked = true
	ds.RevokedAt = blockTime.Unix()
	ds.RevokeReason = tx.GetReason()
	ds.Nonce = tx.GetNonce()

	if err := app.smt.SetDomain(domain, ds); err != nil {
		return execErr(CodeInternal, "state write: %v", err)
	}

	app.logger.Info("domain revoked", "domain", domain, "reason", tx.GetReason())
	return execOK(domainEvent("revoke", domain))
}

// handleRotate replaces a domain's key with a new one, bumping the certificate
// version. The old key authorized this transaction (verified earlier); a revoked
// domain cannot be rotated, and the nonce must be the exact next value.
func (app *App) handleRotate(tx *types.RotateTx, ds *types.DomainState, blockTime time.Time) *abci.ExecTxResult {
	domain := tx.GetDomain()

	if ds.GetRevoked() {
		return execErr(CodeSemantic, "%v", errDomainRevoked)
	}
	if tx.GetNonce() != expectedNonce(ds) {
		return execErr(CodeSemantic, "%v: got %d want %d", errBadNonce, tx.GetNonce(), expectedNonce(ds))
	}

	old := ds.GetCertificate()
	ds.Certificate = &types.Certificate{
		Domain:    domain,
		PublicKey: tx.GetNewPublicKey(),
		Algorithm: tx.GetNewAlgorithm(),
		ValidFrom: blockTime.Unix(),
		Version:   old.GetVersion() + 1,
	}
	ds.Nonce = tx.GetNonce()

	if err := app.smt.SetDomain(domain, ds); err != nil {
		return execErr(CodeInternal, "state write: %v", err)
	}

	app.logger.Info("domain key rotated", "domain", domain, "version", ds.Certificate.Version)
	return execOK(domainEvent("rotate", domain))
}
