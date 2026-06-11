package commands

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/ajablonsk1/blockchain-dpki/cmd/dpki-cli/client"
	"github.com/ajablonsk1/blockchain-dpki/internal/state"
	"github.com/ajablonsk1/blockchain-dpki/internal/types"
)

func newLookupCommand(o *opts) *cobra.Command {
	var (
		domain       string
		outputFormat string
		saveProof    string
		saveCert     string
	)

	cmd := &cobra.Command{
		Use:   "lookup",
		Short: "Look up the certificate of a domain together with a Merkle proof",
		Long: `Look up a domain. The node answers with the current DomainState and a Merkle
proof, which the command verifies locally against the app hash committed in the
next block header — the printed data is authenticated, not just trusted.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			c, err := client.New(o.node)
			if err != nil {
				return err
			}
			chainID, err := o.chainIDFromNode(ctx, c)
			if err != nil {
				return err
			}

			dp, err := c.QueryDomainProof(ctx, domain)
			if err != nil {
				return err
			}
			o.vlogf(cmd, "proof for %q at height %d (%d siblings)", domain, dp.Height, len(dp.Proof.Siblings))

			appHash, err := c.AppHashAt(ctx, dp.Height)
			if err != nil {
				return err
			}

			// Verify locally: the displayed state comes out of the proof, so it is
			// exactly what the app hash commits to.
			ds, present, err := state.VerifyDomainProof(appHash, domain, dp.Proof)
			if err != nil {
				return fmt.Errorf("proof from %s does NOT verify against app hash %X at height %d: %w",
					c.Remote(), appHash, dp.Height, err)
			}
			if present != (dp.State != nil) || (present && !proto.Equal(ds, dp.State)) {
				return fmt.Errorf("node %s returned a state that differs from the proven one", c.Remote())
			}

			if saveProof != "" {
				bundle, err := client.NewProofBundle(chainID, dp, appHash)
				if err != nil {
					return err
				}
				if err := bundle.Save(expandHome(saveProof)); err != nil {
					return err
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "Proof saved to %s (verify with 'dpki-cli verify-offline')\n", saveProof)
			}
			if saveCert != "" {
				if !present {
					return fmt.Errorf("cannot save certificate: domain %s is not registered", domain)
				}
				raw, err := protojson.MarshalOptions{Multiline: true}.Marshal(ds.Certificate)
				if err != nil {
					return fmt.Errorf("marshal certificate: %w", err)
				}
				if err := os.WriteFile(expandHome(saveCert), append(raw, '\n'), 0o644); err != nil {
					return fmt.Errorf("save certificate: %w", err)
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "Certificate saved to %s\n", saveCert)
			}

			switch outputFormat {
			case "json":
				return printLookupJSON(cmd.OutOrStdout(), domain, dp, ds, present, appHash)
			case "text":
				printDomainState(cmd.OutOrStdout(), domain, ds, present)
				out := cmd.OutOrStdout()
				fmt.Fprintf(out, "Height:       %d\n", dp.Height)
				fmt.Fprintf(out, "App hash:     %X\n", appHash)
				fmt.Fprintf(out, "Proof:        %d sibling(s), verified locally against app hash ✓\n", len(dp.Proof.Siblings))
				return nil
			default:
				return fmt.Errorf("unknown --output-format %q (want text or json)", outputFormat)
			}
		},
	}

	cmd.Flags().StringVar(&domain, "domain", "", "domain to look up")
	cmd.Flags().StringVar(&outputFormat, "output-format", "text", "output format: text or json")
	cmd.Flags().StringVar(&saveProof, "save-proof", "", "write the proof bundle to this file for offline verification")
	cmd.Flags().StringVar(&saveCert, "save-cert", "", "write the certificate (protojson) to this file")
	_ = cmd.MarkFlagRequired("domain")
	return cmd
}

// printDomainState renders a DomainState (or its absence) for humans.
func printDomainState(w io.Writer, domain string, ds *types.DomainState, present bool) {
	fmt.Fprintf(w, "Domain:       %s\n", domain)
	if !present {
		fmt.Fprintf(w, "Status:       not registered (non-inclusion proof verified ✓)\n")
		return
	}

	cert := ds.GetCertificate()
	status := "Active"
	if ds.GetRevoked() {
		status = fmt.Sprintf("REVOKED at %s", formatUnix(ds.GetRevokedAt()))
		if r := ds.GetRevokeReason(); r != "" {
			status += fmt.Sprintf(" (reason: %s)", r)
		}
	}
	fmt.Fprintf(w, "Status:       %s\n", status)
	fmt.Fprintf(w, "Public key:   %s\n", hex.EncodeToString(cert.GetPublicKey()))
	fmt.Fprintf(w, "Fingerprint:  %s\n", fingerprint(cert.GetPublicKey()))
	fmt.Fprintf(w, "Algorithm:    %s\n", cert.GetAlgorithm())
	fmt.Fprintf(w, "Version:      %d\n", cert.GetVersion())
	fmt.Fprintf(w, "Nonce:        %d\n", ds.GetNonce())
	fmt.Fprintf(w, "Valid from:   %s\n", formatUnix(cert.GetValidFrom()))
}

// lookupJSON is the machine-readable shape of a lookup result.
type lookupJSON struct {
	Domain   string          `json:"domain"`
	Present  bool            `json:"present"`
	State    json.RawMessage `json:"state,omitempty"` // protojson DomainState
	Height   int64           `json:"height"`
	AppHash  string          `json:"app_hash"`
	Verified bool            `json:"verified"`
}

func printLookupJSON(w io.Writer, domain string, dp *client.DomainProof, ds *types.DomainState, present bool, appHash []byte) error {
	res := lookupJSON{
		Domain:   domain,
		Present:  present,
		Height:   dp.Height,
		AppHash:  hex.EncodeToString(appHash),
		Verified: true, // a failed verification returns an error before printing
	}
	if present {
		raw, err := protojson.Marshal(ds)
		if err != nil {
			return fmt.Errorf("marshal domain state: %w", err)
		}
		res.State = raw
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(res)
}

// formatUnix renders a unix timestamp in UTC, the only timezone used in output.
func formatUnix(ts int64) string {
	return time.Unix(ts, 0).UTC().Format("2006-01-02 15:04:05 UTC")
}
