package main

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/ajablonsk1/blockchain-dpki/internal/verifier"
)

func TestParsePubKey(t *testing.T) {
	if _, err := parsePubKey(""); err == nil {
		t.Fatal("empty pubkey accepted")
	}
	if _, err := parsePubKey("zz"); err == nil {
		t.Fatal("non-hex pubkey accepted")
	}
	b, err := parsePubKey("aabb")
	if err != nil || len(b) != 2 {
		t.Fatalf("parsePubKey(aabb) = %x, %v", b, err)
	}
}

// startTestDNS runs a local DNS server answering TXT from records.
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

// TestRunChallengeCheck_Match runs the CLI verification path against a local DNS
// server that serves the correct record.
func TestRunChallengeCheck_Match(t *testing.T) {
	const domain, chainID, pubHex = "example.com", "test-chain", "aabbccdd"
	pub, _ := parsePubKey(pubHex)
	value := verifier.ChallengeValue(domain, pub, chainID)

	addr := startTestDNS(t, map[string][]string{
		verifier.ChallengeName(domain): {value},
	})

	err := runChallengeCheck([]string{
		"--domain", domain, "--pubkey", pubHex, "--chain-id", chainID, "--resolver", addr,
	})
	if err != nil {
		t.Fatalf("challenge-check (match) = %v, want nil", err)
	}
}

func TestRunChallengeCheck_Mismatch(t *testing.T) {
	const domain, chainID, pubHex = "example.com", "test-chain", "aabbccdd"

	addr := startTestDNS(t, map[string][]string{
		verifier.ChallengeName(domain): {"wrong-value"},
	})

	err := runChallengeCheck([]string{
		"--domain", domain, "--pubkey", pubHex, "--chain-id", chainID, "--resolver", addr,
	})
	if err == nil {
		t.Fatal("challenge-check (mismatch) = nil, want error")
	}
}
