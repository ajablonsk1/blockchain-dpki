package commands

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ajablonsk1/blockchain-dpki/cmd/dpki-cli/client"
	"github.com/ajablonsk1/blockchain-dpki/internal/crypto"
	"github.com/ajablonsk1/blockchain-dpki/internal/types"
)

// txSetup performs the steps every write command starts with: load the signing
// key, connect to the node and learn its chain id.
func (o *opts) txSetup(ctx context.Context, keyfileFlag string) (priv, pub []byte, c *client.Client, chainID string, err error) {
	path, err := o.resolveKeyfile(keyfileFlag)
	if err != nil {
		return nil, nil, nil, "", err
	}
	priv, err = crypto.PrivateKeyFromFile(path)
	if err != nil {
		return nil, nil, nil, "", err
	}
	pub, err = crypto.PublicKeyFromPrivate(priv)
	if err != nil {
		return nil, nil, nil, "", err
	}
	c, err = client.New(o.node)
	if err != nil {
		return nil, nil, nil, "", err
	}
	chainID, err = o.chainIDFromNode(ctx, c)
	if err != nil {
		return nil, nil, nil, "", err
	}
	return priv, pub, c, chainID, nil
}

// signAndBroadcast signs tx, submits it and waits for inclusion in a block.
// With -v it prints the sign bytes and the node's raw verdict.
func (o *opts) signAndBroadcast(cmd *cobra.Command, c *client.Client, tx *types.Transaction, priv []byte) (height int64, txHash []byte, err error) {
	if err := tx.Sign(priv); err != nil {
		return 0, nil, err
	}

	if o.verbose {
		signBytes, err := tx.SignBytes()
		if err == nil {
			o.vlogf(cmd, "sign bytes (%d B): %X", len(signBytes), signBytes)
		}
		o.vlogf(cmd, "signature: %X", tx.Signature)
		o.vlogf(cmd, "broadcasting %s tx for %q to %s", tx.BodyType(), tx.GetDomainFromBody(), c.Remote())
	}

	res, err := c.BroadcastTxCommit(cmd.Context(), tx)
	if err != nil {
		return 0, nil, err
	}
	o.vlogf(cmd, "check_tx code=%d log=%q; tx_result code=%d log=%q; height=%d",
		res.CheckTx.Code, res.CheckTx.Log, res.TxResult.Code, res.TxResult.Log, res.Height)

	if err := client.BroadcastError(res); err != nil {
		return 0, nil, err
	}
	hash, err := tx.Hash()
	if err != nil {
		return res.Height, nil, nil //nolint:nilerr // tx is committed; the local hash is cosmetic
	}
	return res.Height, hash, nil
}

// reportCommitted prints the standard success footer of a write command.
func reportCommitted(cmd *cobra.Command, height int64, txHash []byte) {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Block height: %d\n", height)
	if len(txHash) > 0 {
		fmt.Fprintf(out, "Tx hash:      %X\n", txHash)
	}
}
