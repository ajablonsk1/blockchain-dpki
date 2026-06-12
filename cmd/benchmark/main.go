// Command benchmark measures the DPKI system for the thesis evaluation
// chapter. Network suites (throughput, latency) load a running node or
// testnet; in-process suites (state, proof) measure the state tree directly.
//
// Usage:
//
//	benchmark --suite throughput [--node URL] [--rates 25,50,100,200,400] [--duration 15]
//	benchmark --suite latency    [--node URL] [--latency-txs 100] [--latency-gap-ms 500]
//	benchmark --suite state      [--state-max 100000] [--state-batch 10000]
//	benchmark --suite proof      [--proof-sizes 1000,10000,100000] [--proof-samples 200]
//
// Results are written as JSON to --output (default stdout), one self-contained
// report per invocation, including the environment they were measured on.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type report struct {
	Suite      string        `json:"suite"`
	Timestamp  string        `json:"timestamp"`
	Node       string        `json:"node,omitempty"`
	Env        environment   `json:"env"`
	Throughput []rateResult  `json:"throughput,omitempty"`
	Latency    *latencyStats `json:"latency,omitempty"`
	State      []stateResult `json:"state,omitempty"`
	Proof      []proofResult `json:"proof,omitempty"`
}

func main() {
	var (
		suite    = flag.String("suite", "", "throughput | latency | state | proof")
		node     = flag.String("node", "http://localhost:26657", "node RPC address (network suites)")
		output   = flag.String("output", "", "write the JSON report to this file (default stdout)")
		rates    = flag.String("rates", "25,50,100,200,400", "target send rates in tx/s (throughput)")
		duration = flag.Int("duration", 15, "seconds of load per rate (throughput)")

		latencyTxs   = flag.Int("latency-txs", 100, "transactions to time (latency)")
		latencyGapMs = flag.Int("latency-gap-ms", 500, "pause between transactions (latency)")

		stateMax   = flag.Int("state-max", 100_000, "domains to insert (state)")
		stateBatch = flag.Int("state-batch", 10_000, "measurement granularity (state)")

		proofSizes   = flag.String("proof-sizes", "1000,10000,100000", "tree sizes to sample (proof)")
		proofSamples = flag.Int("proof-samples", 200, "proofs sampled per tree size (proof)")
	)
	flag.Parse()

	rep := report{
		Suite:     *suite,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Env:       captureEnvironment(),
	}

	var err error
	switch *suite {
	case "throughput":
		rep.Node = *node
		var rs []int
		if rs, err = parseInts(*rates); err == nil {
			rep.Throughput, err = runThroughput(*node, rs, time.Duration(*duration)*time.Second)
		}
	case "latency":
		rep.Node = *node
		rep.Latency, err = runLatency(*node, *latencyTxs, time.Duration(*latencyGapMs)*time.Millisecond)
	case "state":
		rep.State, err = runStateSuite(*stateMax, *stateBatch)
	case "proof":
		var sizes []int
		if sizes, err = parseInts(*proofSizes); err == nil {
			rep.Proof, err = runProofSuite(sizes, *proofSamples)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown --suite %q (want throughput, latency, state or proof)\n", *suite)
		flag.Usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "benchmark %s: %v\n", *suite, err)
		os.Exit(1)
	}

	if err := writeReport(*output, &rep); err != nil {
		fmt.Fprintf(os.Stderr, "benchmark: %v\n", err)
		os.Exit(1)
	}
}

// writeReport encodes the report to path, or stdout when path is empty. A
// close error must surface: a truncated report is worse than no report.
func writeReport(path string, rep *report) error {
	out := os.Stdout
	if path != "" {
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		defer func() {
			if cerr := f.Close(); cerr != nil {
				fmt.Fprintf(os.Stderr, "benchmark: close %s: %v\n", path, cerr)
			}
		}()
		out = f
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	return nil
}

func parseInts(csv string) ([]int, error) {
	parts := strings.Split(csv, ",")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		v, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || v <= 0 {
			return nil, fmt.Errorf("invalid list entry %q (want positive integers)", p)
		}
		out = append(out, v)
	}
	return out, nil
}
