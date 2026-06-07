package app

import (
	"fmt"

	abci "github.com/cometbft/cometbft/abci/types"
	"google.golang.org/protobuf/proto"

	"github.com/ajablonsk1/blockchain-dpki/internal/types"
)

// Result codes returned in ABCI responses. Zero means success; every non-zero
// code names the validation stage that rejected the transaction, so a client can
// tell a malformed payload from a bad signature from a semantic conflict.
const (
	CodeOK uint32 = iota
	CodeDecode
	CodeValidation
	CodeChainID
	CodeSignature
	CodeSemantic
	CodeVerification
	CodeInternal
	CodeUnknownQuery
)

// decodeTransaction parses the protobuf wire encoding of a transaction. The wire
// format is exactly proto.Marshal(*types.Transaction).
func decodeTransaction(raw []byte) (*types.Transaction, error) {
	tx := &types.Transaction{}
	if err := proto.Unmarshal(raw, tx); err != nil {
		return nil, fmt.Errorf("decode transaction: %w", err)
	}
	return tx, nil
}

// execOK builds a successful FinalizeBlock per-transaction result.
func execOK(events ...abci.Event) *abci.ExecTxResult {
	return &abci.ExecTxResult{Code: CodeOK, Events: events}
}

// execErr builds a failed FinalizeBlock per-transaction result.
func execErr(code uint32, format string, args ...any) *abci.ExecTxResult {
	return &abci.ExecTxResult{Code: code, Log: fmt.Sprintf(format, args...)}
}

// checkOK and checkErr build CheckTx responses.
func checkOK() *abci.ResponseCheckTx { return &abci.ResponseCheckTx{Code: CodeOK} }

func checkErr(code uint32, format string, args ...any) *abci.ResponseCheckTx {
	return &abci.ResponseCheckTx{Code: code, Log: fmt.Sprintf(format, args...)}
}

// domainEvent builds an ABCI event recording an operation on a domain. These
// events are indexed by CometBFT and let clients subscribe to, say, every
// revocation.
func domainEvent(op, domain string) abci.Event {
	return abci.Event{
		Type: "dpki",
		Attributes: []abci.EventAttribute{
			{Key: "op", Value: op, Index: true},
			{Key: "domain", Value: domain, Index: true},
		},
	}
}
