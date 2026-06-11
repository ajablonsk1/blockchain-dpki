package commands

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/ajablonsk1/blockchain-dpki/cmd/dpki-cli/client"
)

const defaultNode = "http://localhost:26657"

// opts carries the global flags shared by all subcommands. PersistentPreRunE
// resolves them against the optional config file before any RunE fires, with
// precedence: explicit flag > config file > flag default.
type opts struct {
	node    string
	chainID string
	keyfile string // default_keyfile from the config; per-command --keyfile wins
	verbose bool
	cfgFile string
}

// NewRootCommand builds the dpki-cli command tree. Each invocation returns an
// independent tree, so tests can run commands in parallel.
func NewRootCommand() *cobra.Command {
	o := &opts{}

	root := &cobra.Command{
		Use:   "dpki-cli",
		Short: "Client for the DPKI blockchain",
		Long: `dpki-cli is the user-facing client of the DPKI blockchain.

It manages Ed25519 keypairs, registers, rotates and revokes domain
certificates, and looks up certificates together with Merkle proofs that can be
verified offline against a trusted app hash.`,
		SilenceUsage: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return o.load(cmd)
		},
	}

	pf := root.PersistentFlags()
	pf.StringVar(&o.node, "node", defaultNode, "node RPC address")
	pf.StringVar(&o.chainID, "chain-id", "", "chain identifier (default: asked from the node)")
	pf.StringVar(&o.cfgFile, "config", "", "config file (default ~/.dpki/config.yaml)")
	pf.BoolVarP(&o.verbose, "verbose", "v", false, "print transactions, sign bytes and RPC details")

	root.AddCommand(
		newKeysCommand(o),
		newChallengeCommand(o),
		newChallengeCheckCommand(o),
		newRegisterCommand(o),
		newRevokeCommand(o),
		newRotateCommand(o),
		newLookupCommand(o),
		newVerifyCommand(o),
		newVerifyOfflineCommand(o),
		newStatusCommand(o),
	)
	return root
}

// load reads the config file (if any) and fills in flags the user did not set.
func (o *opts) load(cmd *cobra.Command) error {
	v := viper.New()
	switch {
	case o.cfgFile != "":
		v.SetConfigFile(expandHome(o.cfgFile))
	default:
		home, err := os.UserHomeDir()
		if err != nil {
			return nil // no home dir, no default config — flags still work
		}
		v.AddConfigPath(filepath.Join(home, ".dpki"))
		v.SetConfigName("config")
		v.SetConfigType("yaml")
	}

	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if o.cfgFile == "" && errors.As(err, &notFound) {
			return nil // default config is optional
		}
		return fmt.Errorf("read config: %w", err)
	}

	flags := cmd.Flags()
	if !flags.Changed("node") && v.IsSet("node") {
		o.node = v.GetString("node")
	}
	if !flags.Changed("chain-id") && v.IsSet("chain_id") {
		o.chainID = v.GetString("chain_id")
	}
	o.keyfile = v.GetString("default_keyfile")
	return nil
}

// vlogf prints a verbose diagnostic line to stderr when -v is set.
func (o *opts) vlogf(cmd *cobra.Command, format string, args ...any) {
	if !o.verbose {
		return
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "# "+format+"\n", args...)
}

// resolveKeyfile picks the per-command --keyfile value or falls back to
// default_keyfile from the config.
func (o *opts) resolveKeyfile(flagVal string) (string, error) {
	switch {
	case flagVal != "":
		return expandHome(flagVal), nil
	case o.keyfile != "":
		return expandHome(o.keyfile), nil
	default:
		return "", errors.New("--keyfile is required (or set default_keyfile in ~/.dpki/config.yaml)")
	}
}

// chainIDFromNode fetches the node's chain id and cross-checks it against
// --chain-id when the user set one. Transactions must always be built with the
// node's actual chain id, never a hardcoded one.
func (o *opts) chainIDFromNode(ctx context.Context, c *client.Client) (string, error) {
	id, err := c.ChainID(ctx)
	if err != nil {
		return "", err
	}
	if o.chainID != "" && o.chainID != id {
		return "", fmt.Errorf("--chain-id %q does not match the node's chain id %q", o.chainID, id)
	}
	return id, nil
}

// resolveChainID returns --chain-id (or the config value) when set, asking the
// node only as a fallback. Used by commands that can work offline.
func (o *opts) resolveChainID(ctx context.Context) (string, error) {
	if o.chainID != "" {
		return o.chainID, nil
	}
	c, err := client.New(o.node)
	if err != nil {
		return "", err
	}
	id, err := c.ChainID(ctx)
	if err != nil {
		return "", fmt.Errorf("chain id unknown: pass --chain-id or make the node reachable\n  %w", err)
	}
	return id, nil
}

// expandHome rewrites a leading "~/" to the user's home directory.
func expandHome(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(path[1:], "/"))
		}
	}
	return path
}
