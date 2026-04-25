package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	merkle "local/merkle-trees"

	"github.com/tidwall/gjson"
)

const baseURL = "http://localhost:26657"

type QueryResponse struct {
	CertEntry json.RawMessage       `json:"CertEntry"`
	Proof     []merkle.ProofElement `json:"Proof"`
	RootHash  []byte                `json:"RootHash"`
	Index     int                   `json:"Index"`
}

type PKIClient struct {
	http *http.Client
}

func NewPKIClient() *PKIClient {
	return &PKIClient{
		http: &http.Client{Timeout: 10 * time.Second},
	}
}

func (p *PKIClient) RegisterDomain(domain, publicKeyHex, signatureHex string) error {
	tx := fmt.Sprintf("REGISTER|%s|%s|%s", domain, publicKeyHex, signatureHex)
	body, err := p.broadcastTx(tx)
	if err != nil {
		return fmt.Errorf("register failed: %w", err)
	}
	fmt.Println(body)
	return nil
}

func (p *PKIClient) RevokeDomain(domain, signatureHex string) error {
	tx := fmt.Sprintf("REVOKE|%s|%s", domain, signatureHex)
	body, err := p.broadcastTx(tx)
	if err != nil {
		return fmt.Errorf("revoke failed: %w", err)
	}
	fmt.Println(body)
	return nil
}

func (p *PKIClient) LookupDomain(domain string) error {
	resp, err := p.queryDomain(domain)
	if err != nil {
		return fmt.Errorf("lookup failed: %w", err)
	}

	pretty, err := json.MarshalIndent(json.RawMessage(resp.CertEntry), "", "  ")
	if err != nil {
		return fmt.Errorf("formatting response failed: %w", err)
	}
	fmt.Println(string(pretty))
	return nil
}

func (p *PKIClient) VerifyDomain(domain string) error {
	resp, err := p.queryDomain(domain)
	if err != nil {
		return fmt.Errorf("verify failed: %w", err)
	}

	valid := merkle.Verify(resp.RootHash, []byte(resp.CertEntry), resp.Index, resp.Proof)
	if valid {
		fmt.Println("VALID — certificate is in the registry")
	} else {
		fmt.Println("INVALID — proof does not match root")
	}
	return nil
}

func (p *PKIClient) queryDomain(domain string) (*QueryResponse, error) {
	dataHex := hex.EncodeToString([]byte(domain))
	url := fmt.Sprintf("%s/abci_query?data=0x%s", baseURL, dataHex)

	body, err := p.get(url)
	if err != nil {
		return nil, err
	}

	code := gjson.Get(body, "result.response.code").Int()
	if code != 0 {
		log := gjson.Get(body, "result.response.log").String()
		return nil, fmt.Errorf("query error (code %d): %s", code, log)
	}

	value64 := gjson.Get(body, "result.response.value").String()
	value, err := base64.StdEncoding.DecodeString(value64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}

	var resp QueryResponse
	if err := json.Unmarshal(value, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal failed: %w", err)
	}
	return &resp, nil
}

func (p *PKIClient) broadcastTx(tx string) (string, error) {
	txHex := hex.EncodeToString([]byte(tx))
	url := fmt.Sprintf("%s/broadcast_tx_commit?tx=0x%s", baseURL, txHex)
	return p.get(url)
}

func (p *PKIClient) get(url string) (string, error) {
	resp, err := p.http.Get(url)
	if err != nil {
		return "", fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response failed: %w", err)
	}
	return string(body), nil
}

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: pki-client <register|revoke|lookup|verify> [flags]")
	}

	client := NewPKIClient()

	var err error
	switch os.Args[1] {
	case "register":
		err = registerCmd(client)
	case "revoke":
		err = revokeCmd(client)
	case "lookup":
		err = lookupCmd(client)
	case "verify":
		err = verifyCmd(client)
	default:
		fatalf("unknown command: %s", os.Args[1])
	}

	if err != nil {
		fatalf("%v", err)
	}
}

func registerCmd(client *PKIClient) error {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	domain := fs.String("domain", "", "domain to register")
	keyFile := fs.String("keyFile", "", "private key PEM file")
	fs.Parse(os.Args[2:])

	if *domain == "" || *keyFile == "" {
		return fmt.Errorf("register requires --domain and --keyFile")
	}

	privateKey, publicKey, err := readKeyFile(*keyFile)
	if err != nil {
		return err
	}

	publicKeyHex := hex.EncodeToString(publicKey)
	signature := ed25519.Sign(privateKey, []byte(*domain))
	signatureHex := hex.EncodeToString(signature)

	return client.RegisterDomain(*domain, publicKeyHex, signatureHex)
}

func revokeCmd(client *PKIClient) error {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	domain := fs.String("domain", "", "domain to revoke")
	keyFile := fs.String("keyFile", "", "private key PEM file")
	fs.Parse(os.Args[2:])

	if *domain == "" || *keyFile == "" {
		return fmt.Errorf("revoke requires --domain and --keyFile")
	}

	privateKey, _, err := readKeyFile(*keyFile)
	if err != nil {
		return err
	}

	signature := ed25519.Sign(privateKey, []byte(*domain))
	signatureHex := hex.EncodeToString(signature)

	return client.RevokeDomain(*domain, signatureHex)
}

func lookupCmd(client *PKIClient) error {
	fs := flag.NewFlagSet("lookup", flag.ExitOnError)
	domain := fs.String("domain", "", "domain to look up")
	fs.Parse(os.Args[2:])

	if *domain == "" {
		return fmt.Errorf("lookup requires --domain")
	}

	return client.LookupDomain(*domain)
}

func verifyCmd(client *PKIClient) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	domain := fs.String("domain", "", "domain to verify")
	fs.Parse(os.Args[2:])

	if *domain == "" {
		return fmt.Errorf("verify requires --domain")
	}

	return client.VerifyDomain(*domain)
}

func readKeyFile(path string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("reading key file: %w", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, nil, fmt.Errorf("no PEM block found in %s", path)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing private key: %w", err)
	}

	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("key is not Ed25519")
	}

	publicKey := privateKey.Public().(ed25519.PublicKey)
	return privateKey, publicKey, nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
