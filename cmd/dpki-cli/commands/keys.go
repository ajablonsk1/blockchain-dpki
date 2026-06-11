package commands

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/ajablonsk1/blockchain-dpki/internal/crypto"
)

func newKeysCommand(o *opts) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "Manage Ed25519 keypairs",
	}
	cmd.AddCommand(newKeysGenerateCommand(o), newKeysShowCommand(o))
	return cmd
}

func newKeysGenerateCommand(o *opts) *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a new Ed25519 keypair",
		RunE: func(cmd *cobra.Command, _ []string) error {
			path := expandHome(output)
			if _, err := os.Stat(path); err == nil {
				return fmt.Errorf("refusing to overwrite existing key file %s", path)
			}
			if dir := filepath.Dir(path); dir != "." {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					return fmt.Errorf("create key directory: %w", err)
				}
			}

			priv, pub, err := crypto.GenerateEd25519KeyPair()
			if err != nil {
				return err
			}
			if err := crypto.PrivateKeyToFile(path, priv); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Private key saved: %s (mode 0600)\n", path)
			fmt.Fprintf(out, "Public key (hex):  %s\n", hex.EncodeToString(pub))
			fmt.Fprintf(out, "Fingerprint:       %s\n", fingerprint(pub))
			return nil
		},
	}

	cmd.Flags().StringVar(&output, "output", "", "path for the new private key file")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}

func newKeysShowCommand(o *opts) *cobra.Command {
	var keyfile string

	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show the public key and fingerprint of a keypair",
		Long:  "Show the public key and fingerprint of a keypair. The private key itself is never printed.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := o.resolveKeyfile(keyfile)
			if err != nil {
				return err
			}
			priv, err := crypto.PrivateKeyFromFile(path)
			if err != nil {
				return err
			}
			pub, err := crypto.PublicKeyFromPrivate(priv)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Public key (hex): %s\n", hex.EncodeToString(pub))
			fmt.Fprintf(out, "Fingerprint:      %s\n", fingerprint(pub))
			fmt.Fprintf(out, "Algorithm:        Ed25519\n")
			return nil
		},
	}

	cmd.Flags().StringVar(&keyfile, "keyfile", "", "private key file (default: default_keyfile from config)")
	return cmd
}

// fingerprint returns the SHA-256 digest of a public key, hex-encoded.
func fingerprint(pub []byte) string {
	return hex.EncodeToString(crypto.Hash(pub))
}
