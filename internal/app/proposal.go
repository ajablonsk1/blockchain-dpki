package app

import (
	"context"

	abci "github.com/cometbft/cometbft/abci/types"

	"github.com/ajablonsk1/blockchain-dpki/internal/types"
)

// ProcessProposal is the consensus-level admission gate. Every validator runs it
// on a proposed block before voting, and it re-runs the domain-ownership
// verification for each registration the block contains. If any registration
// fails verification the whole block is rejected, so a proposer cannot smuggle
// in an unverified registration by bypassing the mempool (and thus CheckTx).
//
// Like CheckTx, this performs non-deterministic DNS I/O and is therefore a
// pre-consensus gate, kept out of the deterministic FinalizeBlock.
// PrepareProposal keeps its default (the proposer takes mempool transactions in
// order); only ProcessProposal is overridden.
func (app *App) ProcessProposal(ctx context.Context, req *abci.RequestProcessProposal) (*abci.ResponseProcessProposal, error) {
	for _, raw := range req.Txs {
		tx, err := decodeTransaction(raw)
		if err != nil {
			// Undecodable transactions are not rejected here; FinalizeBlock will
			// record them with a non-zero result code without changing state.
			continue
		}
		reg, ok := tx.GetBody().(*types.Transaction_Register)
		if !ok {
			continue
		}
		if err := app.verifier.Verify(ctx, reg.Register); err != nil {
			app.logger.Warn("rejecting proposal: unverified registration",
				"domain", reg.Register.GetCertificate().GetDomain(), "err", err)
			return &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_REJECT}, nil
		}
	}
	return &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_ACCEPT}, nil
}
