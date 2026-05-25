package crypto

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

var ErrEmptyData = errors.New("data is empty")

func Sign(privKey, data []byte) ([]byte, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("sign: %w", ErrInvalidKeySize)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("sign: %w", ErrEmptyData)
	}

	return ed25519.Sign(privKey, data), nil
}

func Verify(pubKey, data, signature []byte) bool {
	if len(pubKey) != ed25519.PublicKeySize {
		return false
	}

	if len(data) == 0 {
		return false
	}

	if len(signature) != ed25519.SignatureSize {
		return false
	}

	return ed25519.Verify(pubKey, data, signature)
}
