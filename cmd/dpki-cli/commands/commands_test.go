package commands

import (
	"bytes"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/ajablonsk1/blockchain-dpki/internal/verifier"
)

// runCLI executes a fresh command tree with args. HOME points at a temp dir so
// a developer's real ~/.dpki/config.yaml cannot leak into tests.
func runCLI(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())

	root := NewRootCommand()
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(args)
	err = root.Execute()
	return out.String(), errOut.String(), err
}

// generateKey runs `keys generate` and returns the keyfile path and the
// public key hex printed by the command.
func generateKey(t *testing.T, dir, name string) (path, pubHex string) {
	t.Helper()
	path = filepath.Join(dir, name)
	out, _, err := runCLI(t, "keys", "generate", "--output", path)
	if err != nil {
		t.Fatalf("keys generate: %v", err)
	}
	for line := range strings.Lines(out) {
		if rest, ok := strings.CutPrefix(line, "Public key (hex):"); ok {
			pubHex = strings.TrimSpace(rest)
		}
	}
	if pubHex == "" {
		t.Fatalf("keys generate printed no public key:\n%s", out)
	}
	return path, pubHex
}

func TestKeysGenerateAndShow(t *testing.T) {
	dir := t.TempDir()
	path, pubHex := generateKey(t, dir, "key.priv")

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat keyfile: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("keyfile mode = %v, want 0600", perm)
	}

	out, _, err := runCLI(t, "keys", "show", "--keyfile", path)
	if err != nil {
		t.Fatalf("keys show: %v", err)
	}
	if !strings.Contains(out, pubHex) {
		t.Errorf("keys show does not print the generated public key:\n%s", out)
	}
	if strings.Contains(out, "Private") {
		t.Errorf("keys show mentions the private key:\n%s", out)
	}
}

func TestKeysGenerateRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	path, _ := generateKey(t, dir, "key.priv")

	if _, _, err := runCLI(t, "keys", "generate", "--output", path); err == nil {
		t.Fatal("keys generate overwrote an existing keyfile")
	}
}

func TestKeysShowBadKeyfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.priv")
	if err := os.WriteFile(path, []byte("too short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCLI(t, "keys", "show", "--keyfile", path); err == nil {
		t.Fatal("keys show accepted a malformed keyfile")
	}
}

func TestChallengePrintsRecord(t *testing.T) {
	dir := t.TempDir()
	path, pubHex := generateKey(t, dir, "key.priv")

	out, _, err := runCLI(t, "challenge", "--domain", "example.com", "--keyfile", path, "--chain-id", "test-chain")
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}

	pub, err := hex.DecodeString(pubHex)
	if err != nil {
		t.Fatal(err)
	}
	want := verifier.ChallengeValue("example.com", pub, "test-chain")
	if !strings.Contains(out, verifier.ChallengeName("example.com")) || !strings.Contains(out, want) {
		t.Errorf("challenge output misses record name or value:\n%s", out)
	}
}

// startTestDNS runs a local DNS server answering TXT queries from records.
func startTestDNS(t *testing.T, records map[string][]string) string {
	t.Helper()
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		for _, q := range r.Question {
			if q.Qtype != dns.TypeTXT {
				continue
			}
			for _, val := range records[strings.TrimSuffix(q.Name, ".")] {
				m.Answer = append(m.Answer, &dns.TXT{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
					Txt: []string{val},
				})
			}
		}
		_ = w.WriteMsg(m)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: mux}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("test DNS did not start")
	}
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestChallengeCheck(t *testing.T) {
	const domain, chainID, pubHex = "example.com", "test-chain", "aabbccdd"
	pub, err := hex.DecodeString(pubHex)
	if err != nil {
		t.Fatal(err)
	}
	value := verifier.ChallengeValue(domain, pub, chainID)

	addr := startTestDNS(t, map[string][]string{
		verifier.ChallengeName(domain): {value},
	})

	if _, _, err := runCLI(t, "challenge-check",
		"--domain", domain, "--pubkey", pubHex, "--chain-id", chainID, "--resolver", addr); err != nil {
		t.Errorf("challenge-check (match) = %v, want nil", err)
	}

	wrongAddr := startTestDNS(t, map[string][]string{
		verifier.ChallengeName(domain): {"wrong-value"},
	})
	if _, _, err := runCLI(t, "challenge-check",
		"--domain", domain, "--pubkey", pubHex, "--chain-id", chainID, "--resolver", wrongAddr); err == nil {
		t.Error("challenge-check (mismatch) = nil, want error")
	}
}

func TestConfigFileProvidesNode(t *testing.T) {
	n := startMockNode(t)

	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("node: "+n.URL+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, _, err := runCLI(t, "status", "--config", cfg)
	if err != nil {
		t.Fatalf("status with config: %v", err)
	}
	if !strings.Contains(out, mockChainID) {
		t.Errorf("status does not report the chain id from the configured node:\n%s", out)
	}
}

func TestNodeDownGivesReadableError(t *testing.T) {
	// A closed listener guarantees a refused connection on a real free port.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	url := "http://" + l.Addr().String()
	_ = l.Close()

	_, _, err = runCLI(t, "status", "--node", url)
	if err == nil {
		t.Fatal("status against a down node succeeded")
	}
	if !strings.Contains(err.Error(), "cannot reach node") || !strings.Contains(err.Error(), "Hint:") {
		t.Errorf("error is not the readable variant: %v", err)
	}
}
