package state

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/ajablonsk1/blockchain-dpki/internal/crypto"
	"github.com/ajablonsk1/blockchain-dpki/internal/types"
	"google.golang.org/protobuf/proto"
)

var (
	ErrNilDomainState   = errors.New("state: domain state is nil")
	ErrInvalidProof     = errors.New("state: proof does not verify against root")
	ErrProofKeyMismatch = errors.New("state: proof key does not match domain")
)

// DomainKey maps a domain name to its 32-byte SMT key. Hashing the domain gives
// fixed-length, well-distributed keys and avoids issues with unusual characters
// in raw domain strings
func DomainKey(domain string) []byte {
	return crypto.Hash([]byte(domain))
}

// marshalDomainState produces the deterministic byte encoding of a DomainState
func marshalDomainState(st *types.DomainState) ([]byte, error) {
	if st == nil {
		return nil, ErrNilDomainState
	}

	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(st)
	if err != nil {
		return nil, fmt.Errorf("marshal domain state: %w", err)
	}
	return b, nil
}

// SetDomain stores st as the state of domain and updates the root.
func (s *SMT) SetDomain(domain string, st *types.DomainState) error {
	b, err := marshalDomainState(st)
	if err != nil {
		return err
	}
	return s.Set(DomainKey(domain), b)
}

// GetDomain returns the DomainState for domain and whether it is present.
func (s *SMT) GetDomain(domain string) (*types.DomainState, bool, error) {
	b, present, err := s.Get(DomainKey(domain))
	if err != nil || !present {
		return nil, present, err
	}

	st := &types.DomainState{}
	if err := proto.Unmarshal(b, st); err != nil {
		return nil, false, fmt.Errorf("unmarshal domain state: %w", err)
	}
	return st, true, nil
}

// ProveDomain returns a compressed proof for domain (inclusion or non-inclusion).
func (s *SMT) ProveDomain(domain string) (*Proof, error) {
	return s.Prove(DomainKey(domain))
}

// VerifyDomainProof verifies p for domain against root, with no access to the
// tree. On success it returns the proven DomainState and present=true for an
// inclusion proof, or (nil, false, nil) for a verified non-inclusion proof
// (domain provably absent). It returns an error if p is malformed, is for a
// different domain, or does not verify against root.
//
// This is the function a relying party (e.g. a TLS client) runs to decide
// whether a certificate is the current, non-revoked binding for a domain, using
// only a trusted root and a proof
func VerifyDomainProof(root []byte, domain string, p *Proof) (*types.DomainState, bool, error) {
	if p == nil {
		return nil, false, ErrInvalidProof
	}

	if !bytes.Equal(p.Key, DomainKey(domain)) {
		return nil, false, ErrProofKeyMismatch
	}

	if !VerifyProof(root, p) {
		return nil, false, ErrInvalidProof
	}

	if p.Value == nil {
		return nil, false, nil // proven absent
	}

	st := &types.DomainState{}
	if err := proto.Unmarshal(p.Value, st); err != nil {
		return nil, false, fmt.Errorf("unmarshal domain state: %w", err)
	}

	return st, true, nil
}
