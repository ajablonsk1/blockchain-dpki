package verifier

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"time"

	"github.com/ajablonsk1/blockchain-dpki/internal/types"
)

// DefaultTimeout bounds a single DNS verification.
const DefaultTimeout = 5 * time.Second

// TXTResolver is the slice of net.Resolver the DNS verifier needs. Abstracting it
// lets tests inject a fake resolver while production uses a real *net.Resolver.
type TXTResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// SystemResolver returns a resolver that uses Go's built-in DNS client
// (PreferGo) rather than cgo/libc, so behaviour and caching are predictable and
// the same on every platform.
func SystemResolver() *net.Resolver {
	return &net.Resolver{PreferGo: true}
}

// DNSVerifier proves domain control via a DNS-01-style challenge: the owner
// publishes ChallengeValue at ChallengeName, and the verifier looks it up. It is
// modeled on ACME DNS-01 (Let's Encrypt).
type DNSVerifier struct {
	resolver TXTResolver
	chainID  string
	timeout  time.Duration
	logger   *slog.Logger
}

var _ Verifier = (*DNSVerifier)(nil)

// NewDNSVerifier builds a verifier bound to chainID (needed to derive the
// expected challenge). A zero timeout falls back to DefaultTimeout, a nil logger
// to a discarding logger.
func NewDNSVerifier(resolver TXTResolver, chainID string, timeout time.Duration, logger *slog.Logger) *DNSVerifier {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &DNSVerifier{resolver: resolver, chainID: chainID, timeout: timeout, logger: logger}
}

// Verify looks up the challenge TXT record for the certificate's domain and
// checks that one of its values equals the expected, key-bound challenge.
func (v *DNSVerifier) Verify(ctx context.Context, tx *types.RegisterTx) error {
	if tx == nil || tx.GetCertificate() == nil {
		return ErrNilRegisterTx
	}
	cert := tx.GetCertificate()
	domain := cert.GetDomain()

	expected := ChallengeValue(domain, cert.GetPublicKey(), v.chainID)
	name := ChallengeName(domain)

	ctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()

	records, err := v.resolver.LookupTXT(ctx, name)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrDNSLookup, name, err)
	}

	if slices.Contains(records, expected) {
		v.logger.Debug("domain ownership verified", "domain", domain)
		return nil
	}

	return fmt.Errorf("%w: %s (checked %d record(s))", ErrChallengeNotFound, name, len(records))
}
