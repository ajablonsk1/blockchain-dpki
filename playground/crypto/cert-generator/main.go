package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type CertsConfig struct {
	Certs []CertConfig `yaml:"certs"`
}

type CertConfig struct {
	Name     string       `yaml:"name"`
	Template CertTemplate `yaml:"template"`
}

type CertTemplate struct {
	Subject               Subject  `yaml:"subject"`
	SignatureAlgorithm    string   `yaml:"signatureAlgorithm"`
	KeyUsage              []string `yaml:"keyUsage"`
	ExtKeyUsage           []string `yaml:"extKeyUsage,omitempty"`
	BasicConstraintsValid bool     `yaml:"basicConstraintsValid"`
	IsCA                  bool     `yaml:"isCa"`
	MaxPathLen            int      `yaml:"maxPathLen,omitempty"`
	DNSNames              []string `yaml:"dnsNames,omitempty"`
}

type Subject struct {
	Organization string `yaml:"organization"`
	CommonName   string `yaml:"commonName"`
}

type GeneratedCert struct {
	Name string
	Cert []byte
}

var keyUsageMap = map[string]x509.KeyUsage{
	"KeyUsageDigitalSignature": x509.KeyUsageDigitalSignature,
	"KeyUsageKeyEncipherment":  x509.KeyUsageKeyEncipherment,
	"KeyUsageCertSign":         x509.KeyUsageCertSign,
	"KeyUsageCRLSign":          x509.KeyUsageCRLSign,
}

var extKeyUsageMap = map[string]x509.ExtKeyUsage{
	"ExtKeyUsageServerAuth": x509.ExtKeyUsageServerAuth,
	"ExtKeyUsageClientAuth": x509.ExtKeyUsageClientAuth,
}

var sigAlgoMap = map[string]x509.SignatureAlgorithm{
	"ed25519": x509.PureEd25519,
}

func main() {
	data, err := os.ReadFile("certs_config.yml")
	if err != nil {
		log.Fatalf("error reading file: %v", err)
	}

	var certsConfig CertsConfig
	if err := yaml.Unmarshal(data, &certsConfig); err != nil {
		log.Fatalf("error unmarshaling yaml: %v", err)
	}

	certs := generateCerts(certsConfig)

	for _, cert := range certs {
		saveCertPEM(cert.Name+".pem", cert.Cert)
	}

	verifyChain(certs)
}

func generateCerts(config CertsConfig) []GeneratedCert {
	var certs []GeneratedCert
	var parent *x509.Certificate
	var parentKey any

	for _, certConfig := range config.Certs {
		template := buildTemplate(&certConfig.Template, parent == nil)
		certBytes, parsed, privKey := createCert(template, parent, parentKey)

		certs = append(certs, GeneratedCert{
			Name: certConfig.Name,
			Cert: certBytes,
		})

		parent = parsed
		parentKey = privKey
	}

	return certs
}

func buildTemplate(config *CertTemplate, isRoot bool) *x509.Certificate {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, limit)

	var notAfter time.Time
	if isRoot {
		notAfter = time.Now().Add(10 * 365 * 24 * time.Hour)
	} else if config.IsCA {
		notAfter = time.Now().Add(3 * 365 * 24 * time.Hour)
	} else {
		notAfter = time.Now().Add(365 * 24 * time.Hour)
	}

	var ku x509.KeyUsage
	for _, usageStr := range config.KeyUsage {
		ku |= keyUsageMap[usageStr]
	}

	var eku []x509.ExtKeyUsage
	for _, extUsageStr := range config.ExtKeyUsage {
		eku = append(eku, extKeyUsageMap[extUsageStr])
	}

	var maxPathLenZero bool
	if config.IsCA && config.MaxPathLen == 0 {
		maxPathLenZero = true
	}

	return &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{config.Subject.Organization}, CommonName: config.Subject.CommonName},
		NotBefore:             time.Now(),
		NotAfter:              notAfter,
		KeyUsage:              ku,
		ExtKeyUsage:           eku,
		BasicConstraintsValid: config.BasicConstraintsValid,
		IsCA:                  config.IsCA,
		MaxPathLen:            config.MaxPathLen,
		MaxPathLenZero:        maxPathLenZero,
		DNSNames:              config.DNSNames,
		SignatureAlgorithm:    sigAlgoMap[config.SignatureAlgorithm],
	}
}

func createCert(template, parent *x509.Certificate, parentKey any) ([]byte, *x509.Certificate, ed25519.PrivateKey) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("error generating ed25519 keys: %v", err)
	}

	if parent == nil {
		parent = template
		parentKey = privKey
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pubKey, parentKey)
	if err != nil {
		log.Fatalf("error creating certificate: %v", err)
	}

	parsed, err := x509.ParseCertificate(certBytes)
	if err != nil {
		log.Fatalf("error parsing certificate: %v", err)
	}

	return certBytes, parsed, privKey
}

func verifyChain(certs []GeneratedCert) {
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()

	for i, cert := range certs {
		parsed, err := x509.ParseCertificate(cert.Cert)
		if err != nil {
			log.Fatalf("error parsing certificate %s: %v", cert.Name, err)
		}
		if i == 0 {
			roots.AddCert(parsed)
		} else if parsed.IsCA {
			intermediates.AddCert(parsed)
		}
	}

	endEntity, err := x509.ParseCertificate(certs[len(certs)-1].Cert)
	if err != nil {
		log.Fatalf("error parsing end entity certificate: %v", err)
	}

	_, err = endEntity.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	})
	if err != nil {
		log.Fatalf("chain verification failed: %v", err)
	}

	log.Println("Chain verified successfully")
}

func saveCertPEM(filename string, certBytes []byte) {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("error creating file %s: %v", filename, err)
	}
	defer file.Close()

	if err := pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		log.Fatalf("error encoding PEM: %v", err)
	}
}
