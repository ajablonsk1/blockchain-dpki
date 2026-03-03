package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"strings"
)

func main() {
	conn, err := tls.Dial("tcp", "google.com:443", &tls.Config{})
	if err != nil {
		log.Fatalf("error during tls connection: %v", err)
	}
	defer func() {
		err := conn.Close()
		if err != nil {
			log.Fatalf("error during closing the connection: %v", err)
		}
	}()

	certs := conn.ConnectionState().PeerCertificates
	for i, cert := range certs {
		fmt.Printf("=== Cert %d ===\n", i)
		fmt.Println("Subject:", cert.Subject)
		fmt.Println("Issuer:", cert.Issuer)
		fmt.Println("Public key algorithm:", cert.PublicKeyAlgorithm.String())
		fmt.Println("Signature algorithm:", cert.SignatureAlgorithm.String())
		fmt.Printf("Validity: from %s to %s\n", cert.NotBefore.String(), cert.NotAfter.String())
		fmt.Println("SANs:")
		for _, dns := range cert.DNSNames {
			fmt.Println(" DNS:", dns)
		}
		for _, ip := range cert.IPAddresses {
			fmt.Println(" IP:", ip)
		}
		fmt.Println("IsCA:", cert.IsCA)

		usages := []struct {
			mask x509.KeyUsage
			name string
		}{
			{x509.KeyUsageDigitalSignature, "DigitalSignature"},
			{x509.KeyUsageContentCommitment, "ContentCommitment"},
			{x509.KeyUsageKeyEncipherment, "KeyEncipherment"},
			{x509.KeyUsageCertSign, "CertSign"},
			{x509.KeyUsageCRLSign, "CRLSign"},
		}
		for _, u := range usages {
			if cert.KeyUsage&u.mask != 0 {
				fmt.Println("  -", u.name)
			}
		}

		extNames := map[x509.ExtKeyUsage]string{
			x509.ExtKeyUsageServerAuth: "ServerAuth",
			x509.ExtKeyUsageClientAuth: "ClientAuth",
		}
		for _, eku := range cert.ExtKeyUsage {
			if name, ok := extNames[eku]; ok {
				fmt.Println("  -", name)
			}
		}
	}

	for i := len(certs) - 1; i >= 0; i-- {
		indent := strings.Repeat("  ", len(certs)-1-i)
		prefix := ""
		if i != len(certs)-1 {
			prefix = "└── "
		}
		fmt.Printf("%s%s%s\n", indent, prefix, certs[i].Subject)
	}
}
