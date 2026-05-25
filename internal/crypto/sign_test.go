package crypto

import (
	"errors"
	"testing"
)

func TestSign_ValidSignatureSize(t *testing.T) {
	priv, _, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	sig, err := Sign(priv, []byte("message"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if len(sig) != Ed25519SignatureSize {
		t.Fatalf("signature size: got %d, want %d", len(sig), Ed25519SignatureSize)
	}
}

func TestSign_EmptyData(t *testing.T) {
	priv, _, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	_, err = Sign(priv, []byte{})
	if err == nil {
		t.Fatal("expected error for empty data, got nil")
	}
	if !errors.Is(err, ErrEmptyData) {
		t.Fatalf("expected ErrEmptyData, got: %v", err)
	}
}

func TestSign_NilData(t *testing.T) {
	priv, _, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	_, err = Sign(priv, nil)
	if err == nil {
		t.Fatal("expected error for nil data, got nil")
	}
	if !errors.Is(err, ErrEmptyData) {
		t.Fatalf("expected ErrEmptyData, got: %v", err)
	}
}

func TestSign_InvalidPrivKeySize(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"too short", []byte{1, 2, 3}},
		{"public key size", make([]byte, Ed25519PublicKeySize)},
		{"too long", make([]byte, 200)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Sign(tt.key, []byte("message"))
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, ErrInvalidKeySize) {
				t.Fatalf("expected ErrInvalidKeySize, got: %v", err)
			}
		})
	}
}

func TestVerify_Valid(t *testing.T) {
	priv, pub, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	msg := []byte("test message")
	sig, err := Sign(priv, msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if !Verify(pub, msg, sig) {
		t.Fatal("Verify returned false for a valid signature")
	}
}

func TestVerify_InvalidPublicKeySize(t *testing.T) {
	priv, pub, _ := GenerateEd25519KeyPair()
	msg := []byte("test message")
	sig, _ := Sign(priv, msg)

	tests := []struct {
		name string
		pub  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"too short", pub[:16]},
		{"too long", append(pub, pub...)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if Verify(tt.pub, msg, sig) {
				t.Fatal("Verify returned true for invalid public key size")
			}
		})
	}
}

func TestVerify_EmptyData(t *testing.T) {
	priv, pub, _ := GenerateEd25519KeyPair()
	sig, _ := Sign(priv, []byte("original"))

	if Verify(pub, []byte{}, sig) {
		t.Fatal("Verify returned true for empty data")
	}
}

func TestVerify_NilData(t *testing.T) {
	priv, pub, _ := GenerateEd25519KeyPair()
	sig, _ := Sign(priv, []byte("original"))

	if Verify(pub, nil, sig) {
		t.Fatal("Verify returned true for nil data")
	}
}

func TestVerify_InvalidSignatureSize(t *testing.T) {
	_, pub, _ := GenerateEd25519KeyPair()
	msg := []byte("test message")

	tests := []struct {
		name string
		sig  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"too short", make([]byte, 32)},
		{"too long", make([]byte, 128)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if Verify(pub, msg, tt.sig) {
				t.Fatalf("Verify returned true for invalid signature size (%d bytes)", len(tt.sig))
			}
		})
	}
}

func TestVerify_WrongPublicKey(t *testing.T) {
	priv, _, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate first key: %v", err)
	}
	_, wrongPub, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate second key: %v", err)
	}

	msg := []byte("test message")
	sig, _ := Sign(priv, msg)

	if Verify(wrongPub, msg, sig) {
		t.Fatal("Verify returned true with a non-matching public key")
	}
}

func TestVerify_TamperedData(t *testing.T) {
	priv, pub, _ := GenerateEd25519KeyPair()
	msg := []byte("original message")
	sig, _ := Sign(priv, msg)

	tampered := []byte("tampered message")
	if Verify(pub, tampered, sig) {
		t.Fatal("Verify returned true for tampered data")
	}
}

func TestVerify_TamperedSignature(t *testing.T) {
	priv, pub, _ := GenerateEd25519KeyPair()
	msg := []byte("test message")
	sig, _ := Sign(priv, msg)

	sig[0] ^= 0xFF
	if Verify(pub, msg, sig) {
		t.Fatal("Verify returned true for a tampered signature")
	}
}

func TestSignVerify_Integration(t *testing.T) {
	priv, pub, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	messages := [][]byte{
		[]byte("short"),
		[]byte("a longer message with more content"),
		make([]byte, 4096),
	}

	for _, msg := range messages {
		sig, err := Sign(priv, msg)
		if err != nil {
			t.Fatalf("sign failed for %d-byte message: %v", len(msg), err)
		}
		if !Verify(pub, msg, sig) {
			t.Fatalf("verify failed for %d-byte message", len(msg))
		}
	}
}
