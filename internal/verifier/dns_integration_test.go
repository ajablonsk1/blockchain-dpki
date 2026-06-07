package verifier

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// startTestDNS runs a real DNS server on an ephemeral 127.0.0.1 UDP port that
// answers TXT queries from the given name->values map (names without the
// trailing dot). It returns the server address and registers cleanup.
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
		t.Fatal("test DNS server did not start")
	}

	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// resolverFor returns a net.Resolver that sends every query to addr, regardless
// of the host's DNS configuration.
func resolverFor(addr string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", addr)
		},
	}
}

// TestDNSVerifier_Integration_RealServer exercises the full path through Go's
// net.Resolver against a real (local) DNS server.
func TestDNSVerifier_Integration_RealServer(t *testing.T) {
	pub := newPub(t)
	challenge := ChallengeValue("example.com", pub, testChainID)

	addr := startTestDNS(t, map[string][]string{
		ChallengeName("example.com"): {challenge},
	})
	v := NewDNSVerifier(resolverFor(addr), testChainID, 3*time.Second, nil)

	if err := v.Verify(context.Background(), registerTx(t, "example.com", pub)); err != nil {
		t.Fatalf("Verify against real DNS = %v, want nil", err)
	}
}

func TestDNSVerifier_Integration_MissingRecord(t *testing.T) {
	pub := newPub(t)
	// Server knows nothing about this domain.
	addr := startTestDNS(t, map[string][]string{})
	v := NewDNSVerifier(resolverFor(addr), testChainID, 3*time.Second, nil)

	err := v.Verify(context.Background(), registerTx(t, "example.com", pub))
	// A missing name surfaces either as a lookup error (NXDOMAIN) or as no
	// matching record; both are verification failures.
	if err == nil {
		t.Fatal("Verify succeeded with no DNS record")
	}
	if !errors.Is(err, ErrChallengeNotFound) && !errors.Is(err, ErrDNSLookup) {
		t.Fatalf("Verify = %v, want ErrChallengeNotFound or ErrDNSLookup", err)
	}
}

func TestDNSVerifier_Integration_MultipleRecordsOneMatches(t *testing.T) {
	pub := newPub(t)
	challenge := ChallengeValue("example.com", pub, testChainID)

	addr := startTestDNS(t, map[string][]string{
		ChallengeName("example.com"): {"decoy-1", challenge, "decoy-2"},
	})
	v := NewDNSVerifier(resolverFor(addr), testChainID, 3*time.Second, nil)

	if err := v.Verify(context.Background(), registerTx(t, "example.com", pub)); err != nil {
		t.Fatalf("Verify with multiple records = %v, want nil", err)
	}
}
