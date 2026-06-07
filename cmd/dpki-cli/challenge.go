package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"slices"

	"github.com/ajablonsk1/blockchain-dpki/internal/verifier"
)

// parsePubKey decodes a hex-encoded public key.
func parsePubKey(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("--pubkey is required (hex-encoded public key)")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("--pubkey is not valid hex: %w", err)
	}
	return b, nil
}

// runChallenge prints the TXT record name and value the domain owner must
// publish to prove control of the domain.
func runChallenge(args []string) error {
	fs := flag.NewFlagSet("challenge", flag.ExitOnError)
	domain := fs.String("domain", "", "domain to register (e.g. example.com)")
	pubHex := fs.String("pubkey", "", "hex-encoded public key from the certificate")
	chainID := fs.String("chain-id", defaultChainID, "chain identifier")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *domain == "" {
		return errors.New("--domain is required")
	}
	pub, err := parsePubKey(*pubHex)
	if err != nil {
		return err
	}

	name := verifier.ChallengeName(*domain)
	value := verifier.ChallengeValue(*domain, pub, *chainID)

	fmt.Fprintf(os.Stdout, "Publish this DNS TXT record, then submit the RegisterTx:\n\n")
	fmt.Fprintf(os.Stdout, "  %s.  IN  TXT  %q\n\n", name, value)
	fmt.Fprintf(os.Stdout, "Tip: set a low TTL (e.g. 60s) for fast propagation; remove it after registration.\n")
	return nil
}

// runChallengeCheck looks up the challenge record and reports whether it matches
// the expected value, helping the user confirm DNS propagation before
// submitting the transaction.
func runChallengeCheck(args []string) error {
	fs := flag.NewFlagSet("challenge-check", flag.ExitOnError)
	domain := fs.String("domain", "", "domain to check")
	pubHex := fs.String("pubkey", "", "hex-encoded public key from the certificate")
	chainID := fs.String("chain-id", defaultChainID, "chain identifier")
	resolverAddr := fs.String("resolver", "", "DNS resolver host:port (default: system resolver)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *domain == "" {
		return errors.New("--domain is required")
	}
	pub, err := parsePubKey(*pubHex)
	if err != nil {
		return err
	}

	resolver := verifier.SystemResolver()
	if *resolverAddr != "" {
		addr := *resolverAddr
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "udp", addr)
			},
		}
	}

	name := verifier.ChallengeName(*domain)
	expected := verifier.ChallengeValue(*domain, pub, *chainID)

	records, err := resolver.LookupTXT(context.Background(), name)
	if err != nil {
		return fmt.Errorf("DNS lookup of %s failed: %w", name, err)
	}
	if slices.Contains(records, expected) {
		fmt.Fprintf(os.Stdout, "OK: %s has the expected challenge record.\n", name)
		return nil
	}

	return fmt.Errorf("MISMATCH: %s does not yet have the expected value %q (found %d record(s))",
		name, expected, len(records))
}
