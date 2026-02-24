package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	var (
		algo = flag.String("algo", "ed25519", "algorithm: ed25519 or ecdsa")
		out  = flag.String("out", "key", "output filename")
	)
	flag.Parse()

	var (
		privatePemFilename = fmt.Sprintf("%s.pem", *out)
		publicPemFilename  = fmt.Sprintf("%s.pub.pem", *out)
	)

	switch *algo {
	case "ed25519":
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatalf("encountered error during key generation: %v", err)
		}
		createPemFromKeys(privateKey, publicKey, *algo, privatePemFilename, publicPemFilename)
	case "ecdsa":
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			log.Fatalf("encountered error during key generation: %v", err)
		}
		publicKey := privateKey.PublicKey
		createPemFromKeys(privateKey, &publicKey, *algo, privatePemFilename, publicPemFilename)
	default:
		log.Fatal("algorithm has to be either ed25519 or ecdsa")
	}

	fmt.Printf("Generated %s key pair: %s, %s\n", *algo, privatePemFilename, publicPemFilename)
}

func createPemFromKeys(privateKey, publicKey any, algorithm, privatePemFilename, publicPemFilename string) {
	b, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		log.Fatalf("encountered error marshalling private %s key: %v", algorithm, err)
	}
	createPemFileFromBytes(b, "PRIVATE KEY", privatePemFilename)

	b, err = x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		log.Fatalf("encountered error marshalling public %s key: %v", algorithm, err)
	}
	createPemFileFromBytes(b, "PUBLIC KEY", publicPemFilename)
}

func createPemFileFromBytes(b []byte, keyType, filename string) {
	block := &pem.Block{
		Type:  keyType,
		Bytes: b,
	}

	err := os.WriteFile(filename, pem.EncodeToMemory(block), 0600)
	if err != nil {
		log.Fatalf("encountered error during PEM file creation: %v", err)
	}
}
