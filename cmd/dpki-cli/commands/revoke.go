package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ajablonsk1/blockchain-dpki/internal/types"
)

func newRevokeCommand(o *opts) *cobra.Command {
	var domain, keyfile, reason string

	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke the certificate of a domain",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			priv, _, c, chainID, err := o.txSetup(ctx, keyfile)
			if err != nil {
				return err
			}

			ds, present, _, err := c.QueryDomain(ctx, domain)
			if err != nil {
				return err
			}
			if !present {
				return fmt.Errorf("domain %s is not registered", domain)
			}
			if ds.Revoked {
				return fmt.Errorf("domain %s is already revoked", domain)
			}
			nonce := ds.Nonce + 1
			o.vlogf(cmd, "current nonce %d, sending revoke with nonce %d", ds.Nonce, nonce)

			tx, err := types.NewRevokeTx(domain, nonce, reason, chainID)
			if err != nil {
				return err
			}

			height, hash, err := o.signAndBroadcast(cmd, c, tx, priv)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Domain %s revoked\n", domain)
			reportCommitted(cmd, height, hash)
			return nil
		},
	}

	cmd.Flags().StringVar(&domain, "domain", "", "domain to revoke")
	cmd.Flags().StringVar(&keyfile, "keyfile", "", "private key file of the current owner key")
	cmd.Flags().StringVar(&reason, "reason", "", "human-readable revocation reason")
	_ = cmd.MarkFlagRequired("domain")
	return cmd
}
