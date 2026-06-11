package commands

import (
	"bufio"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/ajablonsk1/blockchain-dpki/internal/types"
	"github.com/ajablonsk1/blockchain-dpki/internal/verifier"
)

func newRegisterCommand(o *opts) *cobra.Command {
	var (
		domain        string
		keyfile       string
		skipChallenge bool
	)

	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register a domain with the public key of a keypair",
		Long: `Register a domain. The node verifies ownership through the DNS-01 challenge,
so the matching TXT record must be published before the transaction is sent
(see "dpki-cli challenge").`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			priv, pub, c, chainID, err := o.txSetup(ctx, keyfile)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if !skipChallenge {
				name := verifier.ChallengeName(domain)
				value := verifier.ChallengeValue(domain, pub, chainID)
				fmt.Fprintf(out, "Publish this DNS TXT record first:\n\n")
				fmt.Fprintf(out, "  %s.  IN  TXT  %q\n\n", name, value)
				fmt.Fprintf(out, "Press ENTER once the record is live (check with 'dpki-cli challenge-check')...\n")
				if _, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n'); err != nil {
					return fmt.Errorf("aborted: %w", err)
				}
			}

			cert, err := types.NewCertificate(domain, pub, types.Algorithm_ALGORITHM_ED25519, time.Now().Unix())
			if err != nil {
				return err
			}
			tx, err := types.NewRegisterTx(cert, chainID)
			if err != nil {
				return err
			}

			height, hash, err := o.signAndBroadcast(cmd, c, tx, priv)
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "Domain %s registered successfully\n", domain)
			reportCommitted(cmd, height, hash)
			return nil
		},
	}

	cmd.Flags().StringVar(&domain, "domain", "", "domain to register (e.g. example.com)")
	cmd.Flags().StringVar(&keyfile, "keyfile", "", "private key file (default: default_keyfile from config)")
	cmd.Flags().BoolVar(&skipChallenge, "skip-challenge", false, "do not wait for the DNS record prompt (automation; the node still verifies)")
	_ = cmd.MarkFlagRequired("domain")
	return cmd
}
