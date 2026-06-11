package commands

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"slices"

	"github.com/spf13/cobra"

	"github.com/ajablonsk1/blockchain-dpki/internal/crypto"
	"github.com/ajablonsk1/blockchain-dpki/internal/verifier"
)

// challengePubKey resolves the public key for the challenge: an explicit
// --pubkey wins, otherwise it is derived from the keyfile.
func (o *opts) challengePubKey(pubHex, keyfile string) ([]byte, error) {
	if pubHex != "" {
		pub, err := hex.DecodeString(pubHex)
		if err != nil {
			return nil, fmt.Errorf("--pubkey is not valid hex: %w", err)
		}
		return pub, nil
	}
	path, err := o.resolveKeyfile(keyfile)
	if err != nil {
		return nil, errors.New("either --pubkey or --keyfile is required")
	}
	priv, err := crypto.PrivateKeyFromFile(path)
	if err != nil {
		return nil, err
	}
	return crypto.PublicKeyFromPrivate(priv)
}

func newChallengeCommand(o *opts) *cobra.Command {
	var domain, pubHex, keyfile string

	cmd := &cobra.Command{
		Use:   "challenge",
		Short: "Print the DNS TXT record to publish for domain ownership",
		RunE: func(cmd *cobra.Command, _ []string) error {
			pub, err := o.challengePubKey(pubHex, keyfile)
			if err != nil {
				return err
			}
			chainID, err := o.resolveChainID(cmd.Context())
			if err != nil {
				return err
			}

			name := verifier.ChallengeName(domain)
			value := verifier.ChallengeValue(domain, pub, chainID)

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Publish this DNS TXT record, then submit the RegisterTx:\n\n")
			fmt.Fprintf(out, "  %s.  IN  TXT  %q\n\n", name, value)
			fmt.Fprintf(out, "Tip: set a low TTL (e.g. 60s) for fast propagation; remove it after registration.\n")
			return nil
		},
	}

	cmd.Flags().StringVar(&domain, "domain", "", "domain to register (e.g. example.com)")
	cmd.Flags().StringVar(&pubHex, "pubkey", "", "hex-encoded public key (alternative to --keyfile)")
	cmd.Flags().StringVar(&keyfile, "keyfile", "", "private key file to derive the public key from")
	_ = cmd.MarkFlagRequired("domain")
	return cmd
}

func newChallengeCheckCommand(o *opts) *cobra.Command {
	var domain, pubHex, keyfile, resolverAddr string

	cmd := &cobra.Command{
		Use:   "challenge-check",
		Short: "Look up the challenge record and report whether it matches",
		RunE: func(cmd *cobra.Command, _ []string) error {
			pub, err := o.challengePubKey(pubHex, keyfile)
			if err != nil {
				return err
			}
			chainID, err := o.resolveChainID(cmd.Context())
			if err != nil {
				return err
			}

			resolver := verifier.SystemResolver()
			if resolverAddr != "" {
				addr := resolverAddr
				resolver = &net.Resolver{
					PreferGo: true,
					Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
						var d net.Dialer
						return d.DialContext(ctx, "udp", addr)
					},
				}
			}

			name := verifier.ChallengeName(domain)
			expected := verifier.ChallengeValue(domain, pub, chainID)

			records, err := resolver.LookupTXT(cmd.Context(), name)
			if err != nil {
				return fmt.Errorf("DNS lookup of %s failed: %w", name, err)
			}
			if slices.Contains(records, expected) {
				fmt.Fprintf(cmd.OutOrStdout(), "OK: %s has the expected challenge record.\n", name)
				return nil
			}
			return fmt.Errorf("MISMATCH: %s does not yet have the expected value %q (found %d record(s))",
				name, expected, len(records))
		},
	}

	cmd.Flags().StringVar(&domain, "domain", "", "domain to check")
	cmd.Flags().StringVar(&pubHex, "pubkey", "", "hex-encoded public key (alternative to --keyfile)")
	cmd.Flags().StringVar(&keyfile, "keyfile", "", "private key file to derive the public key from")
	cmd.Flags().StringVar(&resolverAddr, "resolver", "", "DNS resolver host:port (default: system resolver)")
	_ = cmd.MarkFlagRequired("domain")
	return cmd
}
