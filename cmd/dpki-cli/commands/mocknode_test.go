package commands

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	abci "github.com/cometbft/cometbft/abci/types"
	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cmtp2p "github.com/cometbft/cometbft/p2p"
	ctypes "github.com/cometbft/cometbft/rpc/core/types"
	rpctypes "github.com/cometbft/cometbft/rpc/jsonrpc/types"
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/ajablonsk1/blockchain-dpki/internal/app"
	"github.com/ajablonsk1/blockchain-dpki/internal/state"
	"github.com/ajablonsk1/blockchain-dpki/internal/verifier"
)

const mockChainID = "mock-chain"

// mockNode serves the subset of the CometBFT JSON-RPC API the CLI uses
// (status, broadcast_tx_commit, abci_query, header) on top of a real app.App.
// Commands under test therefore exercise true proofs and app hashes, with no
// consensus engine: every committed transaction becomes its own block, and the
// next block header is "produced" immediately.
type mockNode struct {
	t *testing.T

	mu        sync.Mutex
	app       *app.App
	height    int64
	headerApp map[int64][]byte // header height -> AppHash field of that header
	txs       int

	URL string
}

func startMockNode(t *testing.T) *mockNode {
	t.Helper()
	a := app.NewApp(state.NewSMT(state.NewMemoryStore()), verifier.AllowAllVerifier(), mockChainID, nil)

	info, err := a.Info(context.Background(), &abci.RequestInfo{})
	if err != nil {
		t.Fatalf("app info: %v", err)
	}
	n := &mockNode{
		t:   t,
		app: a,
		// The genesis app hash (empty tree root) appears in the first header.
		headerApp: map[int64][]byte{1: info.LastBlockAppHash},
	}

	srv := httptest.NewServer(http.HandlerFunc(n.handle))
	t.Cleanup(srv.Close)
	n.URL = srv.URL
	return n
}

// TxsCommitted returns how many transactions the node has included in blocks.
func (n *mockNode) TxsCommitted() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.txs
}

func (n *mockNode) handle(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req rpctypes.RPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var params map[string]json.RawMessage
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	var result any
	switch req.Method {
	case "status":
		result, err = n.status()
	case "abci_query":
		result, err = n.abciQuery(r.Context(), params)
	case "broadcast_tx_commit":
		result, err = n.broadcastTxCommit(r.Context(), params)
	case "header":
		result, err = n.header(params)
	default:
		err = fmt.Errorf("mock node: unsupported method %q", req.Method)
	}

	var resp rpctypes.RPCResponse
	if err != nil {
		resp = rpctypes.NewRPCErrorResponse(req.ID, -32603, err.Error(), "")
	} else {
		resp = rpctypes.NewRPCSuccessResponse(req.ID, result)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (n *mockNode) status() (*ctypes.ResultStatus, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	latest := n.height
	if latest == 0 {
		latest = 1 // genesis header always exists
	}
	return &ctypes.ResultStatus{
		NodeInfo: cmtp2p.DefaultNodeInfo{Network: mockChainID},
		SyncInfo: ctypes.SyncInfo{
			LatestBlockHeight: latest,
			LatestAppHash:     n.headerApp[latest],
		},
		ValidatorInfo: ctypes.ValidatorInfo{PubKey: cmted25519.GenPrivKey().PubKey()},
	}, nil
}

func (n *mockNode) abciQuery(ctx context.Context, params map[string]json.RawMessage) (*ctypes.ResultABCIQuery, error) {
	var path, dataHex string
	if err := json.Unmarshal(params["path"], &path); err != nil {
		return nil, fmt.Errorf("decode path: %w", err)
	}
	if err := json.Unmarshal(params["data"], &dataHex); err != nil {
		return nil, fmt.Errorf("decode data: %w", err)
	}
	data, err := hex.DecodeString(dataHex)
	if err != nil {
		return nil, fmt.Errorf("decode data hex: %w", err)
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	res, err := n.app.Query(ctx, &abci.RequestQuery{Path: path, Data: data})
	if err != nil {
		return nil, err
	}
	return &ctypes.ResultABCIQuery{Response: *res}, nil
}

func (n *mockNode) broadcastTxCommit(ctx context.Context, params map[string]json.RawMessage) (*ctypes.ResultBroadcastTxCommit, error) {
	var txB64 string
	if err := json.Unmarshal(params["tx"], &txB64); err != nil {
		return nil, fmt.Errorf("decode tx: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(txB64)
	if err != nil {
		return nil, fmt.Errorf("decode tx base64: %w", err)
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	check, err := n.app.CheckTx(ctx, &abci.RequestCheckTx{Tx: raw})
	if err != nil {
		return nil, err
	}
	res := &ctypes.ResultBroadcastTxCommit{CheckTx: *check}
	if check.Code != app.CodeOK {
		return res, nil // rejected txs never reach a block
	}

	n.height++
	fin, err := n.app.FinalizeBlock(ctx, &abci.RequestFinalizeBlock{
		Txs:    [][]byte{raw},
		Height: n.height,
		Time:   time.Now().UTC(),
	})
	if err != nil {
		return nil, err
	}
	if _, err := n.app.Commit(ctx, &abci.RequestCommit{}); err != nil {
		return nil, err
	}
	n.headerApp[n.height+1] = fin.AppHash
	n.txs++

	res.TxResult = *fin.TxResults[0]
	res.Height = n.height
	return res, nil
}

func (n *mockNode) header(params map[string]json.RawMessage) (*ctypes.ResultHeader, error) {
	var heightStr string
	if raw, ok := params["height"]; ok {
		if err := json.Unmarshal(raw, &heightStr); err != nil {
			return nil, fmt.Errorf("decode height: %w", err)
		}
	}
	height, err := strconv.ParseInt(heightStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse height: %w", err)
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	appHash, ok := n.headerApp[height]
	if !ok {
		return &ctypes.ResultHeader{}, nil // block not produced yet
	}
	return &ctypes.ResultHeader{Header: &cmttypes.Header{
		ChainID: mockChainID,
		Height:  height,
		AppHash: appHash,
	}}, nil
}
