package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	cfg "github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/privval"
	cmttypes "github.com/cometbft/cometbft/types"
	cmttime "github.com/cometbft/cometbft/types/time"
)

// Port scheme for localhost testnets: node i listens on 26656+10i (P2P) and
// 26657+10i (RPC), so a 4-validator net uses the RPC ports 26657, 26667,
// 26677, 26687.
const testnetPortStride = 10

func testnetP2PPort(i int) int { return 26656 + i*testnetPortStride }
func testnetRPCPort(i int) int { return 26657 + i*testnetPortStride }

// runTestnet dispatches the "testnet" subcommands.
func runTestnet(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: dpkid testnet init [flags]")
	}
	switch args[0] {
	case "init":
		return runTestnetInit(args[1:])
	default:
		return fmt.Errorf("unknown testnet command %q (want init)", args[0])
	}
}

// runTestnetInit generates the homes of an N-validator testnet: per-node
// CometBFT config and unique validator/node keys, plus one genesis naming all
// validators, copied verbatim into every home (the genesis files must be
// byte-identical or nodes reject each other's chain).
func runTestnetInit(args []string) error {
	fs := flag.NewFlagSet("testnet init", flag.ExitOnError)
	validators := fs.Int("validators", 4, "number of validators")
	chainID := fs.String("chain-id", defaultChainID, "chain identifier written into genesis")
	outputDir := fs.String("output-dir", "./testnet-data", "directory for the node homes (node0..nodeN-1)")
	docker := fs.Bool("docker", false, "address peers as node0..nodeN-1 on default ports and listen on 0.0.0.0 (for docker compose)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *validators < 1 {
		return fmt.Errorf("--validators must be >= 1, got %d", *validators)
	}
	if entries, err := os.ReadDir(*outputDir); err == nil && len(entries) > 0 {
		return fmt.Errorf("%s already exists and is not empty; remove it first", *outputDir)
	}

	n := *validators
	configs := make([]*cfg.Config, n)
	genVals := make([]cmttypes.GenesisValidator, n)
	peers := make([]string, n)

	// Pass 1: create homes and keys; collect validator pubkeys and p2p addresses.
	for i := range n {
		home := filepath.Join(*outputDir, fmt.Sprintf("node%d", i))
		config := cfg.DefaultConfig()
		config.SetRoot(home)
		cfg.EnsureRoot(home)
		configs[i] = config

		pv := privval.LoadOrGenFilePV(config.PrivValidatorKeyFile(), config.PrivValidatorStateFile())
		nodeKey, err := p2p.LoadOrGenNodeKey(config.NodeKeyFile())
		if err != nil {
			return fmt.Errorf("node%d key: %w", i, err)
		}
		pubKey, err := pv.GetPubKey()
		if err != nil {
			return fmt.Errorf("node%d validator pubkey: %w", i, err)
		}

		genVals[i] = cmttypes.GenesisValidator{
			Address: pubKey.Address(),
			PubKey:  pubKey,
			Power:   10,
			Name:    fmt.Sprintf("node%d", i),
		}
		if *docker {
			peers[i] = fmt.Sprintf("%s@node%d:26656", nodeKey.ID(), i)
		} else {
			peers[i] = fmt.Sprintf("%s@127.0.0.1:%d", nodeKey.ID(), testnetP2PPort(i))
		}
	}

	genDoc := &cmttypes.GenesisDoc{
		ChainID:         *chainID,
		GenesisTime:     cmttime.Now(),
		ConsensusParams: cmttypes.DefaultConsensusParams(),
		Validators:      genVals,
	}

	// Pass 2: write per-node config (ports, peers) and the shared genesis.
	for i := range n {
		config := configs[i]
		config.Moniker = fmt.Sprintf("node%d", i)
		if *docker {
			config.P2P.ListenAddress = "tcp://0.0.0.0:26656"
			config.RPC.ListenAddress = "tcp://0.0.0.0:26657"
		} else {
			config.P2P.ListenAddress = fmt.Sprintf("tcp://127.0.0.1:%d", testnetP2PPort(i))
			config.RPC.ListenAddress = fmt.Sprintf("tcp://127.0.0.1:%d", testnetRPCPort(i))
		}

		// Everyone peers with everyone but itself. All peers share one IP on
		// localhost, which CometBFT rejects by default.
		others := slices.Concat(peers[:i], peers[i+1:])
		config.P2P.PersistentPeers = strings.Join(others, ",")
		config.P2P.AllowDuplicateIP = true
		config.P2P.AddrBookStrict = false

		cfg.WriteConfigFile(filepath.Join(config.RootDir, "config", "config.toml"), config)
		if err := genDoc.SaveAs(config.GenesisFile()); err != nil {
			return fmt.Errorf("node%d genesis: %w", i, err)
		}
	}

	fmt.Fprintf(os.Stdout, "initialized %d-validator testnet in %s (chain-id %q)\n", n, *outputDir, *chainID)
	if *docker {
		fmt.Fprintf(os.Stdout, "peer addresses use hostnames node0..node%d (docker compose mode)\n", n-1)
	} else {
		ports := make([]string, n)
		for i := range n {
			ports[i] = fmt.Sprintf("%d", testnetRPCPort(i))
		}
		fmt.Fprintf(os.Stdout, "RPC ports: %s\n", strings.Join(ports, ", "))
	}
	return nil
}
