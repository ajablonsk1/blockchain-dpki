package main

import (
	"context"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/ajablonsk1/blockchain-dpki/cmd/dpki-cli/client"
)

type latencyStats struct {
	Txs       int       `json:"txs"`
	GapMs     int       `json:"gap_ms"`
	MeanMs    float64   `json:"mean_ms"`
	P50Ms     float64   `json:"p50_ms"`
	P95Ms     float64   `json:"p95_ms"`
	P99Ms     float64   `json:"p99_ms"`
	MinMs     float64   `json:"min_ms"`
	MaxMs     float64   `json:"max_ms"`
	SamplesMs []float64 `json:"samples_ms"`
}

// runLatency measures end-to-end confirmation latency: the wall time of one
// BroadcastTxCommit, i.e. from submission until the transaction is included in
// a finalized block. Transactions are sent one at a time with a pause in
// between, so each sample lands at an uncorrelated phase of the block interval.
func runLatency(nodeURL string, txs int, gap time.Duration) (*latencyStats, error) {
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

	samples := make([]float64, 0, txs)
	for i := range txs {
		tx, err := factory.register(i)
		if err != nil {
			return nil, err
		}

		start := time.Now()
		res, err := c.BroadcastTxCommit(ctx, tx)
		if err != nil {
			return nil, err
		}
		if err := client.BroadcastError(res); err != nil {
			return nil, fmt.Errorf("tx %d: %w", i, err)
		}
		samples = append(samples, float64(time.Since(start).Microseconds())/1000.0)

		if (i+1)%20 == 0 {
			fmt.Fprintf(os.Stderr, "latency: %d/%d txs\n", i+1, txs)
		}
		time.Sleep(gap)
	}

	sorted := slices.Clone(samples)
	slices.Sort(sorted)
	var sum float64
	for _, s := range sorted {
		sum += s
	}
	return &latencyStats{
		Txs:       len(sorted),
		GapMs:     int(gap.Milliseconds()),
		MeanMs:    sum / float64(len(sorted)),
		P50Ms:     percentile(sorted, 0.50),
		P95Ms:     percentile(sorted, 0.95),
		P99Ms:     percentile(sorted, 0.99),
		MinMs:     sorted[0],
		MaxMs:     sorted[len(sorted)-1],
		SamplesMs: samples,
	}, nil
}

// percentile returns the p-th percentile (0..1) of an ascending-sorted slice
// using nearest-rank.
func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(p*float64(len(sorted))+0.5) - 1
	idx = max(0, min(idx, len(sorted)-1))
	return sorted[idx]
}
