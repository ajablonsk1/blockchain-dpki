package verifier

import (
	"context"

	"github.com/ajablonsk1/blockchain-dpki/internal/types"
)

// MockVerifier is a Verifier for tests and for running a node without real DNS.
// With AllowAll it accepts every registration; otherwise it accepts only domains
// in Allowed. If Err is set it is returned for every call, simulating a failure.
type MockVerifier struct {
	AllowAll bool
	Allowed  map[string]bool
	Err      error
}

var _ Verifier = (*MockVerifier)(nil)

// AllowAllVerifier returns a MockVerifier that accepts every registration. It is
// the default used when a node or test does not configure real verification.
func AllowAllVerifier() *MockVerifier { return &MockVerifier{AllowAll: true} }

func (m *MockVerifier) Verify(_ context.Context, tx *types.RegisterTx) error {
	if m.Err != nil {
		return m.Err
	}
	if tx == nil || tx.GetCertificate() == nil {
		return ErrNilRegisterTx
	}
	if m.AllowAll {
		return nil
	}
	if m.Allowed[tx.GetCertificate().GetDomain()] {
		return nil
	}
	return ErrDomainNotAllowed
}
