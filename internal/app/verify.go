package app

import (
	"errors"
	"fmt"

	"github.com/ajablonsk1/blockchain-dpki/internal/types"
)

var (
	errDomainNotFound  = errors.New("domain not registered")
	errDomainExists    = errors.New("domain already registered")
	errDomainRevoked   = errors.New("domain is revoked")
	errBadNonce        = errors.New("nonce is not the expected next value")
	errStaleNonce      = errors.New("nonce is stale")
	errUnknownTxType   = errors.New("unknown transaction type")
	errSignatureFailed = errors.New("signature verification failed")
)

// ownerPubKey returns the public key whose signature authorizes tx, and the
// current DomainState when one is involved. For a RegisterTx the authorizing key
// is the one embedded in the certificate (the domain does not exist yet). For
// RevokeTx and RotateTx the authorizing key is the one currently bound to the
// domain in state, which is what stops anyone but the current owner from
// revoking or rotating it.
func (app *App) ownerPubKey(tx *types.Transaction) (pubKey []byte, ds *types.DomainState, err error) {
	switch body := tx.GetBody().(type) {
	case *types.Transaction_Register:
		return body.Register.GetCertificate().GetPublicKey(), nil, nil

	case *types.Transaction_Revoke:
		ds, present, err := app.smt.GetDomain(body.Revoke.GetDomain())
		if err != nil {
			return nil, nil, fmt.Errorf("state read: %w", err)
		}
		if !present {
			return nil, nil, errDomainNotFound
		}
		return ds.GetCertificate().GetPublicKey(), ds, nil

	case *types.Transaction_Rotate:
		ds, present, err := app.smt.GetDomain(body.Rotate.GetDomain())
		if err != nil {
			return nil, nil, fmt.Errorf("state read: %w", err)
		}
		if !present {
			return nil, nil, errDomainNotFound
		}
		return ds.GetCertificate().GetPublicKey(), ds, nil

	default:
		return nil, nil, errUnknownTxType
	}
}

// verifySignature authenticates tx against the key that is allowed to authorize
// it. It returns the looked-up DomainState (nil for a RegisterTx) so callers can
// reuse it without a second state read.
func (app *App) verifySignature(tx *types.Transaction) (*types.DomainState, error) {
	pubKey, ds, err := app.ownerPubKey(tx)
	if err != nil {
		return nil, err
	}
	if !tx.Verify(pubKey) {
		return nil, errSignatureFailed
	}
	return ds, nil
}

// expectedNonce is the value a mutation must carry to be applied next: one more
// than the domain's current nonce. A freshly registered domain has nonce 0, so
// its first revoke or rotate must use nonce 1.
func expectedNonce(ds *types.DomainState) uint64 { return ds.GetNonce() + 1 }
