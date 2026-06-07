package app

import (
	"context"
	"time"

	abci "github.com/cometbft/cometbft/abci/types"

	"github.com/ajablonsk1/blockchain-dpki/internal/types"
)

// FinalizeBlock executes every transaction in the block in order and returns the
// per-transaction results together with the resulting application hash (the
// Merkle root). In ABCI 2.0 the app hash is returned here, not from Commit.
//
// Each transaction is applied directly to the tree; there is no separate working
// copy (see ADR 009). A failing transaction returns a non-zero result code and
// leaves state untouched, but does not abort the block: consensus has already
// agreed to include these bytes, and a bad transaction is a rejected
// transaction, not a node crash.
func (app *App) FinalizeBlock(_ context.Context, req *abci.RequestFinalizeBlock) (*abci.ResponseFinalizeBlock, error) {
	app.mu.Lock()
	defer app.mu.Unlock()

	results := make([]*abci.ExecTxResult, len(req.Txs))
	for i, raw := range req.Txs {
		results[i] = app.processTransaction(raw, req.Time)
	}

	app.height = req.Height

	root, err := app.smt.Root()
	if err != nil {
		return nil, err
	}

	return &abci.ResponseFinalizeBlock{
		TxResults: results,
		AppHash:   root,
	}, nil
}

// processTransaction performs full validation and, on success, applies the
// transaction to state. It mirrors CheckTx's checks but enforces the exact next
// nonce and actually mutates the tree. It must be called with app.mu held.
func (app *App) processTransaction(raw []byte, blockTime time.Time) *abci.ExecTxResult {
	tx, err := decodeTransaction(raw)
	if err != nil {
		return execErr(CodeDecode, "%v", err)
	}
	if err := tx.Validate(); err != nil {
		return execErr(CodeValidation, "%v", err)
	}
	if tx.GetChainId() != app.chainID {
		return execErr(CodeChainID, "wrong chain id: got %q want %q", tx.GetChainId(), app.chainID)
	}

	ds, err := app.verifySignature(tx)
	if err != nil {
		return execErr(CodeSignature, "%v", err)
	}

	switch body := tx.GetBody().(type) {
	case *types.Transaction_Register:
		return app.handleRegister(body.Register, blockTime)
	case *types.Transaction_Revoke:
		return app.handleRevoke(body.Revoke, ds, blockTime)
	case *types.Transaction_Rotate:
		return app.handleRotate(body.Rotate, ds, blockTime)
	default:
		return execErr(CodeSemantic, "%v", errUnknownTxType)
	}
}
