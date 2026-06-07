package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	cfg "github.com/cometbft/cometbft/config"
	cmtflags "github.com/cometbft/cometbft/libs/cli/flags"
	cmtlog "github.com/cometbft/cometbft/libs/log"
	nm "github.com/cometbft/cometbft/node"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/privval"
	"github.com/cometbft/cometbft/proxy"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/spf13/viper"

	"github.com/ajablonsk1/blockchain-dpki/internal/app"
	"github.com/ajablonsk1/blockchain-dpki/internal/state"
	"github.com/ajablonsk1/blockchain-dpki/internal/verifier"
)

// runStart loads the node home, builds the DPKI application over an in-memory
// state tree, and starts the CometBFT node. The chain ID is read from the
// genesis file so the application validates transactions consistently across
// restarts (CometBFT replays blocks via FinalizeBlock without re-running
// InitChain).
func runStart(args []string) error {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	home := fs.String("home", defaultHome(), "node home directory")
	noVerify := fs.Bool("no-verify", false, "accept registrations without DNS ownership verification (testing only)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	config, err := loadConfig(*home)
	if err != nil {
		return err
	}

	genDoc, err := cmttypes.GenesisDocFromFile(config.GenesisFile())
	if err != nil {
		return fmt.Errorf("load genesis: %w", err)
	}

	appLogger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	smt := state.NewSMT(state.NewMemoryStore())

	var v verifier.Verifier
	if *noVerify {
		appLogger.Warn("DNS ownership verification disabled (--no-verify); registrations are not authenticated")
		v = verifier.AllowAllVerifier()
	} else {
		v = verifier.NewDNSVerifier(verifier.SystemResolver(), genDoc.ChainID, verifier.DefaultTimeout, appLogger)
	}

	application := app.NewApp(smt, v, genDoc.ChainID, appLogger)

	pv := privval.LoadFilePV(config.PrivValidatorKeyFile(), config.PrivValidatorStateFile())
	nodeKey, err := p2p.LoadNodeKey(config.NodeKeyFile())
	if err != nil {
		return fmt.Errorf("load node key: %w", err)
	}

	logger := cmtlog.NewTMLogger(cmtlog.NewSyncWriter(os.Stdout))
	logger, err = cmtflags.ParseLogLevel(config.LogLevel, logger, cfg.DefaultLogLevel)
	if err != nil {
		return fmt.Errorf("parse log level: %w", err)
	}

	node, err := nm.NewNode(
		config,
		pv,
		nodeKey,
		proxy.NewLocalClientCreator(application),
		nm.DefaultGenesisDocProviderFunc(config),
		cfg.DefaultDBProvider,
		nm.DefaultMetricsProvider(config.Instrumentation),
		logger,
	)
	if err != nil {
		return fmt.Errorf("create node: %w", err)
	}

	if err := node.Start(); err != nil {
		return fmt.Errorf("start node: %w", err)
	}
	defer func() {
		_ = node.Stop()
		node.Wait()
	}()

	fmt.Fprintf(os.Stdout, "dpkid node started (chain-id %q); press Ctrl-C to stop\n", genDoc.ChainID)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	return nil
}

// loadConfig reads config.toml from the node home into a validated Config.
func loadConfig(home string) (*cfg.Config, error) {
	config := cfg.DefaultConfig()
	config.SetRoot(home)

	v := viper.New()
	v.SetConfigFile(fmt.Sprintf("%s/config/config.toml", home))
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := v.Unmarshal(config); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	if err := config.ValidateBasic(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return config, nil
}
