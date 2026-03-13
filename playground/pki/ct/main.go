package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"time"

	"github.com/google/certificate-transparency-go/x509util"
)

func main() {
	conn, err := tls.Dial("tcp", "google.com:443", &tls.Config{})
	if err != nil {
		log.Fatalf("error connecting with dial: %v", err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	for _, cert := range certs {
		fmt.Println("Issuer: ", cert.Issuer)
		fmt.Println("Subject: ", cert.Subject)

		scts, err := x509util.ParseSCTsFromCertificate(cert.Raw)
		if err != nil {
			log.Fatalf("error parsing scts from cert: %v", err)
		}

		fmt.Println("  CT add timestamps: ")
		for _, sct := range scts {
			fmt.Println(" ", time.UnixMilli(int64(sct.Timestamp)))
		}

		fmt.Printf("This log is in %d ct logs\n", len(scts))
		fmt.Println("==========================")
	}
}
