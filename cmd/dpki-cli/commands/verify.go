package commands

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/ajablonsk1/blockchain-dpki/cmd/dpki-cli/client"
	"github.com/ajablonsk1/blockchain-dpki/internal/state"
	"github.com/ajablonsk1/blockchain-dpki/internal/types"
)

// nodeVerdict is the outcome of verifying one node's answer about a domain.
type nodeVerdict struct {
	node    string
	height  int64
	appHash []byte
	state   *types.DomainState // nil when provably absent
	present bool
	err     error
}

func newVerifyCommand(o *opts) *cobra.Command {
	var (
		domain string
		nodes  []string
	)

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify the certificate of a domain against one or more nodes",
		Long: `Verify a domain online. Every node is asked for the state and a Merkle proof;
each proof is verified against the app hash committed in that node's block
headers, and the proven states must agree across nodes. No single node has to
be trusted.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if len(nodes) == 0 {
				nodes = []string{o.node}
			}

			verdicts := make([]nodeVerdict, len(nodes))
			for i, n := range nodes {
				verdicts[i] = verifyOnNode(ctx, n, domain)
			}

			out := cmd.OutOrStdout()
			ok := 0
			for _, v := range verdicts {
				if v.err != nil {
					fmt.Fprintf(out, "✗ %s: %v\n", v.node, v.err)
					continue
				}
				ok++
				fmt.Fprintf(out, "✓ %s: proof valid at height %d, app hash %X\n", v.node, v.height, v.appHash)
			}

			if ok == 0 {
				return fmt.Errorf("verification failed on all %d node(s)", len(nodes))
			}
			if err := checkConsistency(verdicts); err != nil {
				return err
			}

			// All agreeing verdicts prove the same state; show it once.
			for _, v := range verdicts {
				if v.err == nil {
					fmt.Fprintf(out, "\n")
					printDomainState(out, domain, v.state, v.present)
					break
				}
			}
			fmt.Fprintf(out, "\n✓ verified by %d/%d node(s), answers consistent\n", ok, len(nodes))
			if ok < len(nodes) {
				return fmt.Errorf("%d node(s) failed verification", len(nodes)-ok)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&domain, "domain", "", "domain to verify")
	cmd.Flags().StringSliceVar(&nodes, "nodes", nil, "comma-separated node RPC addresses (default: --node)")
	_ = cmd.MarkFlagRequired("domain")
	return cmd
}

// verifyOnNode fetches state + proof from one node and verifies the proof
// against the app hash from that node's headers.
func verifyOnNode(ctx context.Context, nodeURL, domain string) nodeVerdict {
	v := nodeVerdict{node: nodeURL}

	c, err := client.New(nodeURL)
	if err != nil {
		v.err = err
		return v
	}
	dp, err := c.QueryDomainProof(ctx, domain)
	if err != nil {
		v.err = err
		return v
	}
	v.height = dp.Height

	appHash, err := c.AppHashAt(ctx, dp.Height)
	if err != nil {
		v.err = err
		return v
	}
	v.appHash = appHash

	ds, present, err := state.VerifyDomainProof(appHash, domain, dp.Proof)
	if err != nil {
		v.err = fmt.Errorf("proof does not verify against app hash %X: %w", appHash, err)
		return v
	}
	v.state, v.present = ds, present
	return v
}

// checkConsistency rejects the lookup when nodes disagree: different proven
// states, or different app hashes at the same height (a forked or lying node).
func checkConsistency(verdicts []nodeVerdict) error {
	var ref *nodeVerdict
	for i := range verdicts {
		v := &verdicts[i]
		if v.err != nil {
			continue
		}
		if ref == nil {
			ref = v
			continue
		}
		if v.present != ref.present || !proto.Equal(v.state, ref.state) {
			return fmt.Errorf("nodes disagree: %s and %s prove different states for the domain", ref.node, v.node)
		}
		if v.height == ref.height && !strings.EqualFold(hex.EncodeToString(v.appHash), hex.EncodeToString(ref.appHash)) {
			return fmt.Errorf("nodes disagree: %s and %s report different app hashes at height %d", ref.node, v.node, v.height)
		}
	}
	return nil
}

func newVerifyOfflineCommand(o *opts) *cobra.Command {
	var (
		proofFile string
		rootHex   string
		domain    string
		certFile  string
	)

	cmd := &cobra.Command{
		Use:   "verify-offline",
		Short: "Verify a saved proof bundle against a trusted root, without a node",
		Long: `Verify a proof bundle written by 'lookup --save-proof' without any network
access. The trusted root (app hash) must be supplied explicitly — obtaining it
from a source you trust is exactly the point of offline verification; the copy
inside the bundle is informational only.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			bundle, err := client.LoadProofBundle(expandHome(proofFile))
			if err != nil {
				return err
			}
			if domain == "" {
				domain = bundle.Domain
			}
			root, err := hex.DecodeString(rootHex)
			if err != nil {
				return fmt.Errorf("--root is not valid hex: %w", err)
			}
			proof, err := bundle.DecodeProof()
			if err != nil {
				return err
			}
			o.vlogf(cmd, "bundle: chain %s, height %d, recorded app hash %s", bundle.ChainID, bundle.Height, bundle.AppHash)

			ds, present, err := state.VerifyDomainProof(root, domain, proof)
			if err != nil {
				return fmt.Errorf("proof INVALID for %q against root %s: %w", domain, rootHex, err)
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "✓ proof valid against root %s (height %d)\n\n", rootHex, bundle.Height)
			printDomainState(out, domain, ds, present)

			if certFile != "" {
				if !present {
					return fmt.Errorf("--cert given but the proof shows %q is not registered", domain)
				}
				expected, err := loadCertificate(expandHome(certFile))
				if err != nil {
					return err
				}
				if !proto.Equal(ds.GetCertificate(), expected) {
					return fmt.Errorf("certificate in %s does NOT match the proven state", certFile)
				}
				fmt.Fprintf(out, "\n✓ certificate in %s matches the proven state\n", certFile)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&proofFile, "proof", "", "proof bundle file from 'lookup --save-proof'")
	cmd.Flags().StringVar(&rootHex, "root", "", "trusted app hash (hex) to verify against")
	cmd.Flags().StringVar(&domain, "domain", "", "domain the proof should be about (default: from the bundle)")
	cmd.Flags().StringVar(&certFile, "cert", "", "certificate file from 'lookup --save-cert' to compare against")
	_ = cmd.MarkFlagRequired("proof")
	_ = cmd.MarkFlagRequired("root")
	return cmd
}

// loadCertificate reads a protojson certificate written by 'lookup --save-cert'.
func loadCertificate(path string) (*types.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read certificate: %w", err)
	}
	cert := &types.Certificate{}
	if err := protojson.Unmarshal(raw, cert); err != nil {
		return nil, fmt.Errorf("parse certificate %s: %w", path, err)
	}
	return cert, nil
}
