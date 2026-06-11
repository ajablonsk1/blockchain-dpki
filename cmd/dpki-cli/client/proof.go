package client

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/ajablonsk1/blockchain-dpki/internal/state"
)

// ProofBundle is the JSON file written by `lookup --save-proof` and consumed by
// `verify-offline`. It carries everything needed to re-verify a lookup without
// talking to a node. AppHash records the root the proof was issued against, but
// an offline verifier must NOT trust it blindly — it should obtain the root out
// of band (e.g. from a block explorer or several nodes) and pass it explicitly
// (ADR 020).
type ProofBundle struct {
	ChainID string `json:"chain_id"`
	Domain  string `json:"domain"`
	Height  int64  `json:"height"`
	AppHash string `json:"app_hash"` // hex; informational, see doc comment
	Proof   string `json:"proof"`    // base64 of state.Proof.MarshalBinary
}

// NewProofBundle packages a proof query result for offline use.
func NewProofBundle(chainID string, dp *DomainProof, appHash []byte) (*ProofBundle, error) {
	raw, err := dp.Proof.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal proof: %w", err)
	}
	return &ProofBundle{
		ChainID: chainID,
		Domain:  dp.Domain,
		Height:  dp.Height,
		AppHash: hex.EncodeToString(appHash),
		Proof:   base64.StdEncoding.EncodeToString(raw),
	}, nil
}

// DecodeProof returns the Merkle proof carried by the bundle.
func (b *ProofBundle) DecodeProof() (*state.Proof, error) {
	raw, err := base64.StdEncoding.DecodeString(b.Proof)
	if err != nil {
		return nil, fmt.Errorf("decode proof base64: %w", err)
	}
	p := &state.Proof{}
	if err := p.UnmarshalBinary(raw); err != nil {
		return nil, fmt.Errorf("decode proof: %w", err)
	}
	return p, nil
}

// Save writes the bundle as indented JSON.
func (b *ProofBundle) Save(path string) error {
	raw, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal proof bundle: %w", err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
		return fmt.Errorf("save proof bundle: %w", err)
	}
	return nil
}

// LoadProofBundle reads a bundle written by Save.
func LoadProofBundle(path string) (*ProofBundle, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read proof bundle: %w", err)
	}
	b := &ProofBundle{}
	if err := json.Unmarshal(raw, b); err != nil {
		return nil, fmt.Errorf("parse proof bundle %s: %w", path, err)
	}
	return b, nil
}
