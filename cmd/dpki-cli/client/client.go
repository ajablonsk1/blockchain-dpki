package client

import (
	"context"
	"errors"
	"fmt"
	"time"

	rpchttp "github.com/cometbft/cometbft/rpc/client/http"
	ctypes "github.com/cometbft/cometbft/rpc/core/types"
	"google.golang.org/protobuf/proto"

	"github.com/ajablonsk1/blockchain-dpki/internal/app"
	"github.com/ajablonsk1/blockchain-dpki/internal/state"
	"github.com/ajablonsk1/blockchain-dpki/internal/types"
)

// rpcTimeoutSeconds bounds every RPC call. broadcast_tx_commit waits for the
// transaction to land in a block, which CometBFT caps at 10s by default, so the
// client timeout must sit above that.
const rpcTimeoutSeconds = 15

var ErrNoProof = errors.New("node returned no " + app.ProofOpType + " proof")

// Client talks to a single DPKI node over CometBFT JSON-RPC.
type Client struct {
	rpc    *rpchttp.HTTP
	remote string
}

// New builds a client for nodeURL (e.g. http://localhost:26657). It validates
// the address but does not dial; connection errors surface on the first call.
func New(nodeURL string) (*Client, error) {
	rpc, err := rpchttp.NewWithTimeout(nodeURL, "/websocket", rpcTimeoutSeconds)
	if err != nil {
		return nil, fmt.Errorf("invalid node address %q: %w", nodeURL, err)
	}
	return &Client{rpc: rpc, remote: nodeURL}, nil
}

// Remote returns the node URL this client talks to.
func (c *Client) Remote() string { return c.remote }

// connErr wraps a transport-level failure with the node address and a hint, so
// the user sees "which node, what to check" instead of a bare RPC error.
func (c *Client) connErr(op string, err error) error {
	return fmt.Errorf("cannot reach node %s (%s): %w\n  Hint: is the node running? Check the --node flag or 'node' in ~/.dpki/config.yaml", c.remote, op, err)
}

// Status returns the node's /status response (chain id, latest height, app hash).
func (c *Client) Status(ctx context.Context) (*ctypes.ResultStatus, error) {
	st, err := c.rpc.Status(ctx)
	if err != nil {
		return nil, c.connErr("status", err)
	}
	return st, nil
}

// ChainID asks the node which network it serves.
func (c *Client) ChainID(ctx context.Context) (string, error) {
	st, err := c.Status(ctx)
	if err != nil {
		return "", err
	}
	return st.NodeInfo.Network, nil
}

// BroadcastTxCommit submits a signed transaction and waits until it is included
// in a block. A nil error means the RPC round-trip succeeded; the node's verdict
// still sits in the result codes — use BroadcastError to interpret them.
func (c *Client) BroadcastTxCommit(ctx context.Context, tx *types.Transaction) (*ctypes.ResultBroadcastTxCommit, error) {
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(tx)
	if err != nil {
		return nil, fmt.Errorf("marshal transaction: %w", err)
	}
	res, err := c.rpc.BroadcastTxCommit(ctx, raw)
	if err != nil {
		return nil, c.connErr("broadcast_tx_commit", err)
	}
	return res, nil
}

// BroadcastError converts non-zero CheckTx/ExecTx codes into a readable error,
// or nil if the transaction was accepted and executed.
func BroadcastError(res *ctypes.ResultBroadcastTxCommit) error {
	if res.CheckTx.Code != app.CodeOK {
		return fmt.Errorf("transaction rejected by CheckTx (code %d): %s", res.CheckTx.Code, res.CheckTx.Log)
	}
	if res.TxResult.Code != app.CodeOK {
		return fmt.Errorf("transaction failed in block %d (code %d): %s", res.Height, res.TxResult.Code, res.TxResult.Log)
	}
	return nil
}

// QueryDomain returns the current DomainState for domain and whether it is
// registered, plus the height the answer reflects.
func (c *Client) QueryDomain(ctx context.Context, domain string) (*types.DomainState, bool, int64, error) {
	res, err := c.rpc.ABCIQuery(ctx, app.QueryPathDomain, []byte(domain))
	if err != nil {
		return nil, false, 0, c.connErr("abci_query", err)
	}
	q := res.Response
	if q.Code != app.CodeOK {
		return nil, false, 0, fmt.Errorf("query %q on %s: code %d: %s", domain, c.remote, q.Code, q.Log)
	}
	if len(q.Value) == 0 {
		return nil, false, q.Height, nil
	}
	ds := &types.DomainState{}
	if err := proto.Unmarshal(q.Value, ds); err != nil {
		return nil, false, 0, fmt.Errorf("unmarshal domain state: %w", err)
	}
	return ds, true, q.Height, nil
}

// DomainProof is the answer to a /domain/proof query: the state (nil when the
// domain is provably absent), the Merkle proof, and the height of the state the
// proof commits to.
type DomainProof struct {
	Domain string
	State  *types.DomainState // nil for a non-inclusion proof
	Proof  *state.Proof
	Height int64
}

// QueryDomainProof returns the DomainState together with a Merkle proof that
// verifies against the app hash for Height (see AppHashAt).
func (c *Client) QueryDomainProof(ctx context.Context, domain string) (*DomainProof, error) {
	res, err := c.rpc.ABCIQuery(ctx, app.QueryPathDomainProof, []byte(domain))
	if err != nil {
		return nil, c.connErr("abci_query", err)
	}
	q := res.Response
	if q.Code != app.CodeOK {
		return nil, fmt.Errorf("query %q on %s: code %d: %s", domain, c.remote, q.Code, q.Log)
	}
	if q.ProofOps == nil || len(q.ProofOps.Ops) != 1 || q.ProofOps.Ops[0].Type != app.ProofOpType {
		return nil, fmt.Errorf("query %q on %s: %w", domain, c.remote, ErrNoProof)
	}

	p := &state.Proof{}
	if err := p.UnmarshalBinary(q.ProofOps.Ops[0].Data); err != nil {
		return nil, fmt.Errorf("decode proof: %w", err)
	}

	dp := &DomainProof{Domain: domain, Proof: p, Height: q.Height}
	if len(q.Value) > 0 {
		ds := &types.DomainState{}
		if err := proto.Unmarshal(q.Value, ds); err != nil {
			return nil, fmt.Errorf("unmarshal domain state: %w", err)
		}
		dp.State = ds
	}
	return dp, nil
}

// AppHashAt returns the app hash committing the state after block height. That
// hash lives in the header of the NEXT block, so when height is the chain tip
// this polls briefly until the next block (~1s block time) is produced.
func (c *Client) AppHashAt(ctx context.Context, height int64) ([]byte, error) {
	next := height + 1
	var lastErr error
	for range 8 {
		h, err := c.rpc.Header(ctx, &next)
		if err == nil && h.Header != nil {
			return h.Header.AppHash, nil
		}
		if err == nil {
			err = fmt.Errorf("block %d not yet produced", next)
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return nil, c.connErr(fmt.Sprintf("header at height %d", next), lastErr)
}
