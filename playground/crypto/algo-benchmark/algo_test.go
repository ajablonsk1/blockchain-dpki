package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"testing"
)

const MessageFilename = "message.txt"

func BenchmarkECDSAKeyGeneration(b *testing.B) {
	for b.Loop() {
		_, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			b.Fatalf("error during ecdsa key generation: %v", err)
		}
	}
}

func BenchmarkEd25519KeyGeneration(b *testing.B) {
	for b.Loop() {
		_, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			b.Fatalf("error during ed25519 key generation: %v", err)
		}
	}
}

func BenchmarkECDSAKeySign(b *testing.B) {
	bytes, err := os.ReadFile(MessageFilename)
	if err != nil {
		b.Fatalf("error opening message file: %v", err)
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("error during ecdsa key generation: %v", err)
	}

	b.ResetTimer()
	for b.Loop() {
		hashedFile := sha256.Sum256(bytes)
		_, err := ecdsa.SignASN1(rand.Reader, privateKey, hashedFile[:])
		if err != nil {
			b.Fatalf("error signing message: %v", err)
		}
	}
}

func BenchmarkEd25519KeySign(b *testing.B) {
	bytes, err := os.ReadFile(MessageFilename)
	if err != nil {
		b.Fatalf("error opening message file: %v", err)
	}

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("error during ed25519 key generation: %v", err)
	}

	b.ResetTimer()
	for b.Loop() {
		_ = ed25519.Sign(privateKey, bytes)
	}
}

func BenchmarkECDSAKeyVerify(b *testing.B) {
	bytes, err := os.ReadFile(MessageFilename)
	if err != nil {
		b.Fatalf("error opening message file: %v", err)
	}
	hashedFile := sha256.Sum256(bytes)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("error during ecdsa key generation: %v", err)
	}

	signedMessage, err := ecdsa.SignASN1(rand.Reader, privateKey, hashedFile[:])
	if err != nil {
		b.Fatalf("error signing message: %v", err)
	}

	b.ResetTimer()
	for b.Loop() {
		_ = ecdsa.VerifyASN1(&privateKey.PublicKey, hashedFile[:], signedMessage)
	}
}

func BenchmarkEd25519KeyVerify(b *testing.B) {
	bytes, err := os.ReadFile(MessageFilename)
	if err != nil {
		b.Fatalf("error opening message file: %v", err)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("error during ed25519 key generation: %v", err)
	}

	signedMessage := ed25519.Sign(privateKey, bytes)

	b.ResetTimer()
	for b.Loop() {
		_ = ed25519.Verify(publicKey, bytes, signedMessage)
	}
}
