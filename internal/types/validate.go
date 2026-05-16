package types

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const (
	// RFC 1035
	MaxDomainLength = 253
	MaxLabelLength  = 63
	// RFC 8032
	Ed25519KeySize = 32
	Ed25519SigSize = 64
	// App limits
	MinValidTimestamp = 1577836800 // 2020-01-01 UTC
	MaxReasonLength   = 256
	MaxChainIDLength  = 50
)

// regex for one label; RFC 1035
var labelRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

var (
	// domain
	ErrEmptyDomain         = errors.New("domain is empty")
	ErrDomainTooLong       = errors.New("domain exceeds max length")
	ErrInvalidDomainFormat = errors.New("domain has invalid format")

	// key
	ErrInvalidKeySize        = errors.New("public key has invalid size")
	ErrInvalidSignatureSize  = errors.New("signature has invalid size")
	ErrUnknownAlgorithm      = errors.New("algorithm is unspecified or unknown")
	ErrAlgorithmNotSupported = errors.New("algorithm is not supported")

	// cert
	ErrNilCertificate   = errors.New("certificate is nil")
	ErrInvalidTimestamp = errors.New("timestamp is invalid")
	ErrReasonTooLong    = errors.New("reason exceeds max length")

	// transaction
	ErrNilTransaction         = errors.New("transaction is nil")
	ErrNilRegisterTx          = errors.New("register tx is nil")
	ErrNilRevokeTx            = errors.New("revoke tx is nil")
	ErrNilRotateTx            = errors.New("rotate tx is nil")
	ErrNilTransactionBody     = errors.New("transaction body is nil")
	ErrUnknownTransactionType = errors.New("transaction type is unknown")
	ErrNonceEqualZero         = errors.New("nonce equals zero")
	ErrInvalidChainId        = errors.New("chain id is invalid")
)

func validateDomain(domain string) error {
	if domain == "" {
		return ErrEmptyDomain
	}

	if len(domain) > MaxDomainLength {
		return fmt.Errorf("%w: %d > %d", ErrDomainTooLong, len(domain), MaxDomainLength)
	}

	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return fmt.Errorf("%w: leading/trailing dot", ErrInvalidDomainFormat)
	}

	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return fmt.Errorf("%w: must have at least one dot", ErrInvalidDomainFormat)
	}

	for _, label := range labels {
		if len(label) > MaxLabelLength {
			return fmt.Errorf("%w: label %q too long", ErrInvalidDomainFormat, label)
		}
		if !labelRegex.MatchString(label) {
			return fmt.Errorf("%w: invalid label %q", ErrInvalidDomainFormat, label)
		}
	}

	return nil
}

func validatePublicKey(key []byte, algo Algorithm) error {
	if algo == Algorithm_ALGORITHM_UNSPECIFIED {
		return ErrUnknownAlgorithm
	}

	switch algo {
	case Algorithm_ALGORITHM_ED25519:
		if len(key) != Ed25519KeySize {
			return fmt.Errorf("%w: ed25519 expect %d bytes, got %d", ErrInvalidKeySize, Ed25519KeySize, len(key))
		}
	case Algorithm_ALGORITHM_ECDSA_P256:
		return ErrAlgorithmNotSupported
	default:
		return fmt.Errorf("%w: %v", ErrUnknownAlgorithm, algo)
	}

	return nil
}

func (c *Certificate) Validate() error {
	if c == nil {
		return ErrNilCertificate
	}

	if err := validateDomain(c.GetDomain()); err != nil {
		return fmt.Errorf("certificate: %w", err)
	}

	if err := validatePublicKey(c.GetPublicKey(), c.GetAlgorithm()); err != nil {
		return fmt.Errorf("certificate: %w", err)
	}

	if c.GetValidFrom() < MinValidTimestamp {
		return fmt.Errorf("%w: valid_from too early (%d, min %d)",
			ErrInvalidTimestamp, c.GetValidFrom(), MinValidTimestamp)
	}

	return nil
}

func (r *RegisterTx) Validate() error {
	if r == nil {
		return ErrNilRegisterTx
	}

	if err := r.GetCertificate().Validate(); err != nil {
		return fmt.Errorf("register: %w", err)
	}

	return nil
}

func (r *RevokeTx) Validate() error {
	if r == nil {
		return ErrNilRevokeTx
	}

	if err := validateDomain(r.GetDomain()); err != nil {
		return fmt.Errorf("revoke: %w", err)
	}

	if r.GetNonce() == 0 {
		return fmt.Errorf("revoke: %w", ErrNonceEqualZero)
	}

	if len(r.GetReason()) > MaxReasonLength {
		return fmt.Errorf("revoke: %w", ErrReasonTooLong)
	}

	return nil
}

func (r *RotateTx) Validate() error {
	if r == nil {
		return ErrNilRotateTx
	}

	if err := validateDomain(r.GetDomain()); err != nil {
		return fmt.Errorf("rotate: %w", err)
	}

	if r.GetNonce() == 0 {
		return fmt.Errorf("rotate: %w", ErrNonceEqualZero)
	}

	if err := validatePublicKey(r.GetNewPublicKey(), r.GetNewAlgorithm()); err != nil {
		return fmt.Errorf("rotate: %w", err)
	}

	return nil
}

func (tx *Transaction) Validate() error {
	if tx == nil {
		return ErrNilTransaction
	}

	sig := tx.GetSignature()
	if len(sig) > 0 && len(sig) != Ed25519SigSize {
		return fmt.Errorf("transaction: %w", ErrInvalidSignatureSize)
	}

	chainId := tx.GetChainId()
	if chainId == "" || len(chainId) > MaxChainIDLength {
		return fmt.Errorf("transaction: %w", ErrInvalidChainId)
	}

	switch body := tx.GetBody().(type) {
	case *Transaction_Register:
		if body.Register == nil {
			return fmt.Errorf("transaction: %w", ErrNilRegisterTx)
		}

		if err := body.Register.Validate(); err != nil {
			return fmt.Errorf("transaction: %w", err)
		}
	case *Transaction_Revoke:
		if body.Revoke == nil {
			return fmt.Errorf("transaction: %w", ErrNilRevokeTx)
		}

		if err := body.Revoke.Validate(); err != nil {
			return fmt.Errorf("transaction: %w", err)
		}
	case *Transaction_Rotate:
		if body.Rotate == nil {
			return fmt.Errorf("transaction: %w", ErrNilRotateTx)
		}

		if err := body.Rotate.Validate(); err != nil {
			return fmt.Errorf("transaction: %w", err)
		}
	case nil:
		return ErrNilTransactionBody
	default:
		return ErrUnknownTransactionType
	}

	return nil
}
