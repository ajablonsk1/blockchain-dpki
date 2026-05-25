package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
)

const (
	Ed25519PublicKeySize  = ed25519.PublicKeySize
	Ed25519PrivateKeySize = ed25519.PrivateKeySize
	Ed25519SignatureSize  = ed25519.SignatureSize
	Ed25519SeedSize       = ed25519.SeedSize
)

var (
	ErrInvalidKeySize       = errors.New("key has invalid size")
	ErrInvalidSignatureSize = errors.New("signature has invalid size")
	ErrInsecurePermissions  = errors.New("key file has insecure permissions")
)

func GenerateEd25519KeyPair() (priv []byte, pub []byte, err error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ed25519 keypair: %w", err)
	}
	return privKey, pubKey, nil
}

func PrivateKeyToFile(path string, key []byte) error {
	if len(key) != Ed25519PrivateKeySize {
		return fmt.Errorf("save private key: %w (expected %d, got %d)",
			ErrInvalidKeySize, Ed25519PrivateKeySize, len(key))
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return fmt.Errorf("save private key: %w", err)
	}
	return nil
}

func PrivateKeyFromFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}

	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("read private key: %w (mode %v)",
			ErrInsecurePermissions, info.Mode().Perm())
	}

	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}

	if len(key) != Ed25519PrivateKeySize {
		return nil, fmt.Errorf("read private key: %w (expected %d, got %d)",
			ErrInvalidKeySize, Ed25519PrivateKeySize, len(key))
	}

	return key, nil
}

func PublicKeyFromPrivate(priv []byte) ([]byte, error) {
	if len(priv) != Ed25519PrivateKeySize {
		return nil, fmt.Errorf("public from private: %w", ErrInvalidKeySize)
	}
	return priv[Ed25519SeedSize:], nil
}
