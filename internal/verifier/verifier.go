package verifier

import (
	"context"
	"errors"

	"github.com/ajablonsk1/blockchain-dpki/internal/types"
)

// Verification errors. They are sentinel values so callers can match on the
// cause; the DNS verifier wraps lookup failures around ErrDNSLookup.
var (
	ErrChallengeNotFound = errors.New("verifier: no matching challenge TXT record")
	ErrDNSLookup         = errors.New("verifier: DNS lookup failed")
	ErrDomainNotAllowed  = errors.New("verifier: domain not allowed")
	ErrNilRegisterTx     = errors.New("verifier: register tx is nil")
)

// Verifier decides whether the submitter of a RegisterTx actually controls the
// domain it tries to claim. It is what turns the DPKI from Trust-On-First-Use
// (first writer wins) into an authenticated registry.
//
// Verification is non-deterministic external I/O (a DNS lookup) and therefore
// MUST be used only as a pre-consensus admission gate (CheckTx, ProcessProposal),
// never inside FinalizeBlock. The application calls Verify on Register
// transactions before they are admitted; once a transaction is in a finalized
// block its inclusion is the record of verification.
type Verifier interface {
	// Verify returns nil if the registrant provably controls the domain, or an
	// error describing why verification failed. It must not mutate any state.
	Verify(ctx context.Context, tx *types.RegisterTx) error
}
