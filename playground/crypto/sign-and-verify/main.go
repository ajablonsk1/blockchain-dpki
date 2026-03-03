package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	mode := flag.String("mode", "sign", "sign|verify")
	key := flag.String("key", "key.pem", "pem filename (sign->private key; verify->public key)")
	message := flag.String("message", "", "message to be signed")
	signature := flag.String("signature", "message.sig", "filename of the output signature")
	flag.Parse()

	if *key == "" || *message == "" {
		log.Println("key and name flag are required and can't be empty")
		flag.Usage()
		os.Exit(1)
	}

	switch *mode {
	case "sign":
		signatureBytes := createSignature(*key, *message)
		err := os.WriteFile(*signature, signatureBytes, 0600)
		if err != nil {
			log.Fatalf("error writing signature to a file: %v", err)
		}
	case "verify":
		signatureBytes, err := os.ReadFile(*signature)
		if err != nil {
			log.Fatalf("error reading signature file: %v", err)
		}
		verified := verifySignature(*key, *message, signatureBytes)

		if verified {
			fmt.Println("Signature valid!")
		} else {
			fmt.Println("Signature invalid!")
		}
	default:
		log.Fatalf("unsupported mode type: %s", *mode)
	}
}

func createSignature(keyFilename, message string) []byte {
	pemBytes := getPemBytesFromFilename(keyFilename)

	privateKey, err := x509.ParsePKCS8PrivateKey(pemBytes)
	if err != nil {
		log.Fatalf("error parsing private key: %v", err)
	}

	var signature []byte
	switch key := privateKey.(type) {
	case ed25519.PrivateKey:
		signature = ed25519.Sign(key, []byte(message))
	case *ecdsa.PrivateKey:
		hash := sha256.Sum256([]byte(message))
		signature, err = ecdsa.SignASN1(rand.Reader, key, hash[:])
		if err != nil {
			log.Fatalf("error creating a signature: %v", err)
		}
	default:
		log.Fatalf("unsupported key type: %T", key)
	}

	return signature
}

func verifySignature(keyFilename, message string, signatureBytes []byte) bool {
	pemBytes := getPemBytesFromFilename(keyFilename)

	publicKey, err := x509.ParsePKIXPublicKey(pemBytes)
	if err != nil {
		log.Fatalf("error parsing public key: %v", err)
	}

	var verified bool
	switch key := publicKey.(type) {
	case ed25519.PublicKey:
		verified = ed25519.Verify(key, []byte(message), signatureBytes)
	case *ecdsa.PublicKey:
		hash := sha256.Sum256([]byte(message))
		verified = ecdsa.VerifyASN1(key, hash[:], signatureBytes)
	default:
		log.Fatalf("unsupported key type: %T", key)
	}

	return verified
}

func getPemBytesFromFilename(keyFilename string) []byte {
	pemBytes, err := os.ReadFile(keyFilename)
	if err != nil {
		log.Fatalf("error reading pem file: %v", err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		log.Fatal("failed to decode pem block; invalid pem file")
	}

	return block.Bytes
}
