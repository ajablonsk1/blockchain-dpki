package commands

import (
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ajablonsk1/blockchain-dpki/internal/crypto"
	"github.com/ajablonsk1/blockchain-dpki/internal/types"
)

func newRotateCommand(o *opts) *cobra.Command {
	var domain, keyfile, newKeyfile string

	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Rotate the key of a domain to a new keypair",
		Long: `Rotate the key of a domain. The transaction carries the NEW public key but is
signed with the CURRENT (old) private key — only the present owner may rotate.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			priv, _, c, chainID, err := o.txSetup(ctx, keyfile)
			if err != nil {
				return err
			}

			newPriv, err := crypto.PrivateKeyFromFile(expandHome(newKeyfile))
			if err != nil {
				return fmt.Errorf("new key: %w", err)
			}
			newPub, err := crypto.PublicKeyFromPrivate(newPriv)
			if err != nil {
				return fmt.Errorf("new key: %w", err)
			}

			ds, present, _, err := c.QueryDomain(ctx, domain)
			if err != nil {
				return err
			}
			if !present {
				return fmt.Errorf("domain %s is not registered", domain)
			}
			if ds.Revoked {
				return fmt.Errorf("domain %s is revoked; a revoked binding is permanent and cannot be rotated", domain)
			}
			nonce := ds.Nonce + 1
			o.vlogf(cmd, "current nonce %d, sending rotate with nonce %d", ds.Nonce, nonce)

			tx, err := types.NewRotateTx(domain, nonce, newPub, types.Algorithm_ALGORITHM_ED25519, chainID)
			if err != nil {
				return err
			}

			// The OLD key signs: ownership of the current key authorizes the rotation.
			height, hash, err := o.signAndBroadcast(cmd, c, tx, priv)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Domain %s rotated to new key\n", domain)
			fmt.Fprintf(out, "New public key: %s\n", hex.EncodeToString(newPub))
			reportCommitted(cmd, height, hash)
			return nil
		},
	}

	cmd.Flags().StringVar(&domain, "domain", "", "domain whose key to rotate")
	cmd.Flags().StringVar(&keyfile, "keyfile", "", "CURRENT private key file (signs the transaction)")
	cmd.Flags().StringVar(&newKeyfile, "new-keyfile", "", "NEW private key file (its public key replaces the current one)")
	_ = cmd.MarkFlagRequired("domain")
	_ = cmd.MarkFlagRequired("new-keyfile")
	return cmd
}
