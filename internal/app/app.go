package app

import (
	"context"
	"log/slog"
	"sync"

	abci "github.com/cometbft/cometbft/abci/types"

	"github.com/ajablonsk1/blockchain-dpki/internal/state"
)

// Version identifiers reported in the ABCI Info response.
const (
	AppName    = "dpki"
	AppVersion = "0.1.0"
	// AppProtocolVersion is the on-chain application protocol version. Bump it
	// only on a state-machine-breaking change (encoding, validation, hashing).
	AppProtocolVersion uint64 = 1
)

// App is the DPKI ABCI 2.0 application. It maps domain names to their
// DomainState through a Sparse Merkle Tree and exposes the consensus-agreed root
// hash as the application hash. Transactions register a domain, revoke it, or
// rotate its key; every transaction is fully validated (syntactic, semantic and
// cryptographic) before it is allowed to change state.
//
// App embeds abci.BaseApplication so unused ABCI methods (snapshots, vote
// extensions, the default PrepareProposal/ProcessProposal) keep their no-op
// behaviour and only the methods that matter here are overridden.
//
// Concurrency: CometBFT drives the consensus, mempool and query connections
// concurrently, so all access to the tree is serialized by mu. FinalizeBlock and
// Commit take the write lock; CheckTx, Query and Info take the read lock.
type App struct {
	abci.BaseApplication

	mu      sync.RWMutex
	smt     *state.SMT
	chainID string
	height  int64
	logger  *slog.Logger
}

var _ abci.Application = (*App)(nil)

// NewApp returns an App backed by smt for the given chainID. chainID is supplied
// by the node (from the genesis file) rather than learned from InitChain, so the
// application validates transactions correctly after a restart, when CometBFT
// replays blocks via FinalizeBlock without calling InitChain again. A nil logger
// is replaced with a discarding logger.
func NewApp(smt *state.SMT, chainID string, logger *slog.Logger) *App {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &App{smt: smt, chainID: chainID, logger: logger}
}

// Info reports the application version and the last committed height and app
// hash. CometBFT uses the height and hash to decide how many blocks to replay
// after a restart.
func (app *App) Info(_ context.Context, _ *abci.RequestInfo) (*abci.ResponseInfo, error) {
	app.mu.RLock()
	defer app.mu.RUnlock()

	root, err := app.smt.Root()
	if err != nil {
		return nil, err
	}

	return &abci.ResponseInfo{
		Data:             AppName,
		Version:          AppVersion,
		AppVersion:       AppProtocolVersion,
		LastBlockHeight:  app.height,
		LastBlockAppHash: root,
	}, nil
}

// InitChain runs once at genesis. The MVP starts from an empty state, so it only
// asserts that the genesis chain ID matches the one the node was built with and
// returns the empty-tree app hash.
func (app *App) InitChain(_ context.Context, req *abci.RequestInitChain) (*abci.ResponseInitChain, error) {
	app.mu.Lock()
	defer app.mu.Unlock()

	if req.ChainId != app.chainID {
		app.logger.Warn("genesis chain id differs from configured chain id",
			"genesis", req.ChainId, "configured", app.chainID)
		app.chainID = req.ChainId
	}

	root, err := app.smt.Root()
	if err != nil {
		return nil, err
	}

	return &abci.ResponseInitChain{AppHash: root}, nil
}

// Commit finalizes the block. Because FinalizeBlock applies each transaction
// directly to the tree (there is no separate working copy — see ADR 009), the
// state is already durable by the time Commit is called, so this is a no-op that
// simply acknowledges the block.
func (app *App) Commit(_ context.Context, _ *abci.RequestCommit) (*abci.ResponseCommit, error) {
	return &abci.ResponseCommit{}, nil
}
