package main

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/ajablonsk1/blockchain-dpki/internal/crypto"
	"github.com/ajablonsk1/blockchain-dpki/internal/state"
	"github.com/ajablonsk1/blockchain-dpki/internal/types"
)

type stateResult struct {
	Domains        int     `json:"domains"`
	StoreKeys      int     `json:"store_keys"`
	StoreBytes     int64   `json:"store_bytes"`
	BytesPerDomain float64 `json:"bytes_per_domain"`
	AvgInsertUs    float64 `json:"avg_insert_us"` // over the last batch
	HeapAllocMB    float64 `json:"heap_alloc_mb"`
}

// runStateSuite grows an in-process SMT to maxDomains in batches and records,
// at every batch boundary, the store volume, the per-insert cost and the heap
// footprint — the raw data for the "state growth is linear in N" claim.
func runStateSuite(maxDomains, batch int) ([]stateResult, error) {
	store := state.NewMemoryStore()
	smt := state.NewSMT(store)

	_, pub, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		return nil, err
	}
	validFrom := time.Now().Unix()

	var results []stateResult
	for n := 0; n < maxDomains; {
		batchStart := time.Now()
		end := min(n+batch, maxDomains)
		batchSize := end - n
		for ; n < end; n++ {
			domain := fmt.Sprintf("bench%07d.example.com", n)
			cert, err := types.NewCertificate(domain, pub, types.Algorithm_ALGORITHM_ED25519, validFrom)
			if err != nil {
				return nil, err
			}
			if err := smt.SetDomain(domain, &types.DomainState{Certificate: cert}); err != nil {
				return nil, err
			}
		}
		batchDur := time.Since(batchStart)

		runtime.GC()
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)

		bytes := store.SizeBytes()
		res := stateResult{
			Domains:        n,
			StoreKeys:      store.Len(),
			StoreBytes:     bytes,
			BytesPerDomain: float64(bytes) / float64(n),
			AvgInsertUs:    float64(batchDur.Microseconds()) / float64(batchSize),
			HeapAllocMB:    float64(ms.HeapAlloc) / (1024 * 1024),
		}
		results = append(results, res)
		fmt.Fprintf(os.Stderr, "state: %d domains, %.1f MB store, %.0f µs/insert\n",
			n, float64(bytes)/(1024*1024), res.AvgInsertUs)
	}
	return results, nil
}
