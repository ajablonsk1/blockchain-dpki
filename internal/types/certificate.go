package types

import (
	"fmt"

	"github.com/ajablonsk1/blockchain-dpki/internal/crypto"
	"google.golang.org/protobuf/proto"
)

// SignBytes returns the deterministic byte representation of the certificate.
// Unlike Transaction, Certificate has no Signature field to exclude.
func (c *Certificate) SignBytes() ([]byte, error) {
	if c == nil {
		return nil, ErrNilCertificate
	}

	opts := proto.MarshalOptions{Deterministic: true}
	bytes, err := opts.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("cert sign bytes: %w", err)
	}

	return bytes, nil
}

// Hash returns SHA-256 of the deterministic certificate serialization.
func (c *Certificate) Hash() ([]byte, error) {
	if c == nil {
		return nil, ErrNilCertificate
	}

	bytes, err := c.SignBytes()
	if err != nil {
		return nil, fmt.Errorf("cert hash: %w", err)
	}

	return crypto.Hash(bytes), nil
}
