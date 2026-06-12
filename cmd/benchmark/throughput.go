package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ajablonsk1/blockchain-dpki/cmd/dpki-cli/client"
	"github.com/ajablonsk1/blockchain-dpki/internal/app"
)

// senders is the number of concurrent submitters; without them the
// single-threaded HTTP round-trip, not the node, would cap the send rate.
const senders = 8

type rateResult struct {
	TargetTPS       int     `json:"target_tps"`
	SendSeconds     float64 `json:"send_seconds"`
	Sent            int     `json:"sent"`
	AcceptedCheckTx int     `json:"accepted_checktx"`
	RejectedCheckTx int     `json:"rejected_checktx"`
	Committed       int     `json:"committed"`
	Blocks          int     `json:"blocks_with_txs"`
	AvgBlockTxs     float64 `json:"avg_block_txs"`
	MaxBlockTxs     int     `json:"max_block_txs"`
	ActualTPS       float64 `json:"actual_tps"`
	DrainSeconds    float64 `json:"drain_seconds"`
}

// runThroughput pushes signed RegisterTx at each target rate for dur, then
// waits for the mempool to drain and counts what actually landed in blocks.
// ActualTPS is committed txs divided by the first-to-last block timestamp
// span, so it measures the chain, not the load generator.
func runThroughput(nodeURL string, rates []int, dur time.Duration) ([]rateResult, error) {
	ctx := context.Background()
	c, err := client.New(nodeURL)
	if err != nil {
		return nil, err
	}
	chainID, err := c.ChainID(ctx)
	if err != nil {
		return nil, err
	}
	factory, err := newTxFactory(chainID)
	if err != nil {
		return nil, err
	}

	results := make([]rateResult, 0, len(rates))
	seq := 0
	for _, rate := range rates {
		fmt.Fprintf(os.Stderr, "throughput: rate %d tx/s for %v...\n", rate, dur)

		status, err := c.Status(ctx)
		if err != nil {
			return nil, err
		}
		startHeight := status.SyncInfo.LatestBlockHeight

		res := rateResult{TargetTPS: rate}
		var accepted, rejected atomic.Int64

		// A ticker paces tokens; a small worker pool turns them into RPCs.
		tokens := make(chan int, rate)
		var wg sync.WaitGroup
		for range senders {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for s := range tokens {
					tx, err := factory.register(s)
					if err != nil {
						continue
					}
					br, err := c.BroadcastTxSync(ctx, tx)
					if err != nil || br.Code != app.CodeOK {
						rejected.Add(1)
						continue
					}
					accepted.Add(1)
				}
			}()
		}

		sendStart := time.Now()
		ticker := time.NewTicker(time.Second / time.Duration(rate))
		for time.Since(sendStart) < dur {
			<-ticker.C
			tokens <- seq
			seq++
			res.Sent++
		}
		ticker.Stop()
		close(tokens)
		wg.Wait()
		res.SendSeconds = time.Since(sendStart).Seconds()
		res.AcceptedCheckTx = int(accepted.Load())
		res.RejectedCheckTx = int(rejected.Load())

		// Let the chain work through the backlog before measuring.
		drainStart := time.Now()
		if err := waitMempoolDrain(ctx, c, 120*time.Second); err != nil {
			return nil, err
		}
		res.DrainSeconds = time.Since(drainStart).Seconds()

		status, err = c.Status(ctx)
		if err != nil {
			return nil, err
		}
		var firstTxBlock, lastTxBlock time.Time
		for h := startHeight + 1; h <= status.SyncInfo.LatestBlockHeight; h++ {
			txs, blockTime, err := c.BlockTxStats(ctx, h)
			if err != nil {
				return nil, err
			}
			if txs == 0 {
				continue
			}
			if firstTxBlock.IsZero() {
				firstTxBlock = blockTime
			}
			lastTxBlock = blockTime
			res.Committed += txs
			res.Blocks++
			res.MaxBlockTxs = max(res.MaxBlockTxs, txs)
		}
		if res.Blocks > 0 {
			res.AvgBlockTxs = float64(res.Committed) / float64(res.Blocks)
		}
		if span := lastTxBlock.Sub(firstTxBlock).Seconds(); span > 0 {
			res.ActualTPS = float64(res.Committed) / span
		} else {
			// All txs landed in one block; the block interval bounds the rate.
			res.ActualTPS = float64(res.Committed) / res.SendSeconds
		}

		results = append(results, res)
		fmt.Fprintf(os.Stderr, "throughput: rate %d -> committed %d in %d blocks, actual %.1f tx/s\n",
			rate, res.Committed, res.Blocks, res.ActualTPS)
	}
	return results, nil
}

func waitMempoolDrain(ctx context.Context, c *client.Client, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		n, err := c.UnconfirmedTxCount(ctx)
		if err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("mempool did not drain within %v", timeout)
}
