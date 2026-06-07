package main

import (
	"flag"
	"fmt"
	"os"

	cfg "github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/privval"
	cmttypes "github.com/cometbft/cometbft/types"
	cmttime "github.com/cometbft/cometbft/types/time"
)

// runInit generates a fresh node home: CometBFT config.toml, validator and node
// keys, and a genesis file with a single validator (this node) and the given
// chain ID. It is idempotent for keys (existing keys are reused) but always
// (re)writes the genesis so the chain ID takes effect.
func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	home := fs.String("home", defaultHome(), "node home directory")
	chainID := fs.String("chain-id", defaultChainID, "chain identifier written into genesis")
	if err := fs.Parse(args); err != nil {
		return err
	}

	config := cfg.DefaultConfig()
	config.SetRoot(*home)
	// EnsureRoot creates config/ and data/ and writes a default config.toml.
	cfg.EnsureRoot(*home)

	// Validator key (consensus signing) and node key (p2p identity).
	pv := privval.LoadOrGenFilePV(config.PrivValidatorKeyFile(), config.PrivValidatorStateFile())
	if _, err := p2p.LoadOrGenNodeKey(config.NodeKeyFile()); err != nil {
		return fmt.Errorf("node key: %w", err)
	}

	pubKey, err := pv.GetPubKey()
	if err != nil {
		return fmt.Errorf("validator pubkey: %w", err)
	}

	genDoc := &cmttypes.GenesisDoc{
		ChainID:         *chainID,
		GenesisTime:     cmttime.Now(),
		ConsensusParams: cmttypes.DefaultConsensusParams(),
		Validators: []cmttypes.GenesisValidator{{
			Address: pubKey.Address(),
			PubKey:  pubKey,
			Power:   10,
			Name:    "node0",
		}},
	}
	if err := genDoc.SaveAs(config.GenesisFile()); err != nil {
		return fmt.Errorf("save genesis: %w", err)
	}

	fmt.Fprintf(os.Stdout, "initialized dpkid home at %s (chain-id %q)\n", *home, *chainID)
	return nil
}
