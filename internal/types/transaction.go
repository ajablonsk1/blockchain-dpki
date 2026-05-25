package types

import (
	"fmt"

	"github.com/ajablonsk1/blockchain-dpki/internal/crypto"
	"google.golang.org/protobuf/proto"
)

// SignBytes returns a deterministic protobuf serialization of the transaction
// with the Signature field zeroed out. The result is the canonical byte
// representation that is both signed and hashed.
func (tx *Transaction) SignBytes() ([]byte, error) {
	if tx == nil {
		return nil, ErrNilTransaction
	}

	clone := proto.Clone(tx).(*Transaction)
	clone.Signature = nil

	opts := proto.MarshalOptions{Deterministic: true}
	bytes, err := opts.Marshal(clone)
	if err != nil {
		return nil, fmt.Errorf("sign bytes: %w", err)
	}

	return bytes, nil
}

// Hash returns the SHA-256 digest of SignBytes. Two transactions with the same
// fields (excluding Signature) produce the same hash.
func (tx *Transaction) Hash() ([]byte, error) {
	bytes, err := tx.SignBytes()
	if err != nil {
		return nil, fmt.Errorf("tx hash: %w", err)
	}

	return crypto.Hash(bytes), nil
}

// Sign computes SignBytes, signs them with privKey (Ed25519), and stores the
// result in tx.Signature. It overwrites any previously set signature.
func (tx *Transaction) Sign(privKey []byte) error {
	bytes, err := tx.SignBytes()
	if err != nil {
		return fmt.Errorf("tx sign: %w", err)
	}

	signature, err := crypto.Sign(privKey, bytes)
	if err != nil {
		return fmt.Errorf("tx sign: %w", err)
	}

	tx.Signature = signature

	return nil
}

// Verify checks that tx.Signature is a valid Ed25519 signature over SignBytes
// produced by the private key corresponding to pubKey.
func (tx *Transaction) Verify(pubKey []byte) bool {
	bytes, err := tx.SignBytes()
	if err != nil {
		return false
	}

	return crypto.Verify(pubKey, bytes, tx.Signature)
}

// BodyType returns a human-readable string identifying the oneof variant set
// in the transaction body ("register", "revoke", "rotate"), or "" if the
// transaction is nil or the body is unset.
func (tx *Transaction) BodyType() string {
	if tx == nil {
		return ""
	}

	switch tx.GetBody().(type) {
	case *Transaction_Register:
		return "register"
	case *Transaction_Revoke:
		return "revoke"
	case *Transaction_Rotate:
		return "rotate"
	case nil:
		return ""
	default:
		return ""
	}
}

// GetDomainFromBody extracts the domain field from whichever body variant is
// set, returning "" for a nil transaction or an empty/unknown body.
func (tx *Transaction) GetDomainFromBody() string {
	if tx == nil {
		return ""
	}

	switch body := tx.GetBody().(type) {
	case *Transaction_Register:
		return body.Register.GetCertificate().GetDomain()
	case *Transaction_Revoke:
		return body.Revoke.GetDomain()
	case *Transaction_Rotate:
		return body.Rotate.GetDomain()
	case nil:
		return ""
	default:
		return ""
	}
}
