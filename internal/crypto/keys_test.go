package crypto

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateEd25519KeyPair_ValidSizes(t *testing.T) {
	priv, pub, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(priv) != Ed25519PrivateKeySize {
		t.Errorf("private key size: got %d, want %d", len(priv), Ed25519PrivateKeySize)
	}
	if len(pub) != Ed25519PublicKeySize {
		t.Errorf("public key size: got %d, want %d", len(pub), Ed25519PublicKeySize)
	}
}

func TestGenerateEd25519KeyPair_Uniqueness(t *testing.T) {
	seen := make(map[string]bool)

	for i := range 100 {
		priv, _, err := GenerateEd25519KeyPair()
		if err != nil {
			t.Fatalf("generate failed at iteration %d: %v", i, err)
		}

		key := string(priv)
		if seen[key] {
			t.Fatalf("duplicate private key generated at iteration %d", i)
		}
		seen[key] = true
	}
}

func TestGenerateEd25519KeyPair_PublicMatchesPrivate(t *testing.T) {
	priv, pub, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}

	expectedPub := priv[Ed25519SeedSize:]
	if string(pub) != string(expectedPub) {
		t.Fatal("public key does not match last 32 bytes of private key")
	}
}

func TestPublicKeyFromPrivate_MatchesGenerated(t *testing.T) {
	priv, pub, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}

	derived, err := PublicKeyFromPrivate(priv)
	if err != nil {
		t.Fatalf("derive failed: %v", err)
	}

	if string(derived) != string(pub) {
		t.Fatal("derived public key does not match generated public key")
	}
}

func TestPublicKeyFromPrivate_InvalidSize(t *testing.T) {
	tests := []struct {
		name string
		priv []byte
	}{
		{"empty", []byte{}},
		{"nil", nil},
		{"too short", []byte{1, 2, 3}},
		{"too long", make([]byte, 100)},
		{"public key size", make([]byte, Ed25519PublicKeySize)}, // 32, ale powinno być 64
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := PublicKeyFromPrivate(tt.priv)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, ErrInvalidKeySize) {
				t.Fatalf("expected ErrInvalidKeySize, got: %v", err)
			}
		})
	}
}

func TestPublicKeyFromPrivate_Deterministic(t *testing.T) {
	priv, _, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}

	pub1, _ := PublicKeyFromPrivate(priv)
	pub2, _ := PublicKeyFromPrivate(priv)

	if string(pub1) != string(pub2) {
		t.Fatal("PublicKeyFromPrivate is not deterministic")
	}
}

func TestPrivateKey_Roundtrip(t *testing.T) {
	priv, _, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}

	path := filepath.Join(t.TempDir(), "test.priv")

	if err := PrivateKeyToFile(path, priv); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	loaded, err := PrivateKeyFromFile(path)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}

	if string(loaded) != string(priv) {
		t.Fatal("roundtrip mismatch: loaded key does not match saved key")
	}
}

func TestPrivateKeyToFile_FilePermissions(t *testing.T) {
	priv, _, _ := GenerateEd25519KeyPair()
	path := filepath.Join(t.TempDir(), "test.priv")

	if err := PrivateKeyToFile(path, priv); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}

	mode := info.Mode().Perm()
	if mode != 0o600 {
		t.Errorf("file permissions: got %o, want %o", mode, 0o600)
	}
}

func TestPrivateKeyToFile_InvalidKeySize(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
	}{
		{"empty", []byte{}},
		{"nil", nil},
		{"too short", []byte{1, 2, 3}},
		{"public key size", make([]byte, Ed25519PublicKeySize)},
		{"too long", make([]byte, 200)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "test.priv")
			err := PrivateKeyToFile(path, tt.key)

			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, ErrInvalidKeySize) {
				t.Fatalf("expected ErrInvalidKeySize, got: %v", err)
			}

			// Plik nie powinien zostać utworzony
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("file was created despite invalid key")
			}
		})
	}
}

func TestPrivateKeyFromFile_NonExistent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonexistent.priv")

	_, err := PrivateKeyFromFile(path)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected os.ErrNotExist, got: %v", err)
	}
}

func TestPrivateKeyFromFile_WrongSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wrong.priv")
	if err := os.WriteFile(path, []byte{1, 2, 3}, 0o600); err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	_, err := PrivateKeyFromFile(path)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrInvalidKeySize) {
		t.Fatalf("expected ErrInvalidKeySize, got: %v", err)
	}
}

func TestPrivateKeyFromFile_InsecurePermissions(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping permission test")
	}

	priv, _, _ := GenerateEd25519KeyPair()
	path := filepath.Join(t.TempDir(), "insecure.priv")

	if err := os.WriteFile(path, priv, 0o644); err != nil { // za szerokie prawa
		t.Fatalf("setup failed: %v", err)
	}

	_, err := PrivateKeyFromFile(path)
	if err == nil {
		t.Fatal("expected error for insecure permissions, got nil")
	}
	if !errors.Is(err, ErrInsecurePermissions) {
		t.Fatalf("expected ErrInsecurePermissions, got: %v", err)
	}
}

func TestKeysIntegration_FullFlow(t *testing.T) {
	priv, pub, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	path := filepath.Join(t.TempDir(), "alice.priv")
	if err := PrivateKeyToFile(path, priv); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := PrivateKeyFromFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	derivedPub, err := PublicKeyFromPrivate(loaded)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}

	if string(derivedPub) != string(pub) {
		t.Fatal("end-to-end: derived public does not match original")
	}

	msg := []byte("test message")
	sig := ed25519.Sign(ed25519.PrivateKey(loaded), msg)

	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		t.Fatal("end-to-end: signature with loaded key does not verify with original public key")
	}
}
