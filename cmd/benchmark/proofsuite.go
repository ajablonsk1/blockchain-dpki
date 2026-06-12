package main

import (
	"fmt"
	"math/rand/v2"
	"os"
	"slices"
	"time"

	"github.com/ajablonsk1/blockchain-dpki/internal/crypto"
	"github.com/ajablonsk1/blockchain-dpki/internal/state"
	"github.com/ajablonsk1/blockchain-dpki/internal/types"
)

type proofResult struct {
	Domains               int     `json:"domains"`
	Samples               int     `json:"samples"`
	AvgProofBytes         float64 `json:"avg_proof_bytes"`
	MaxProofBytes         int     `json:"max_proof_bytes"`
	AvgSiblings           float64 `json:"avg_siblings"`
	AvgVerifyUs           float64 `json:"avg_verify_us"`
	NonInclProofBytes     float64 `json:"non_inclusion_avg_proof_bytes"`
	NonInclAvgVerifyUs    float64 `json:"non_inclusion_avg_verify_us"`
	NonInclSamplesChecked int     `json:"non_inclusion_samples"`
}

// runProofSuite grows one SMT through the requested sizes (ascending) and, at
// each size, samples random inclusion and non-inclusion proofs: wire size,
// sibling count and offline verification time. The expected curve is O(log N)
// proof size — the number a relying party pays per lookup.
func runProofSuite(sizes []int, samples int) ([]proofResult, error) {
	sizes = slices.Clone(sizes)
	slices.Sort(sizes)

	smt := state.NewSMT(state.NewMemoryStore())
	_, pub, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		return nil, err
	}
	validFrom := time.Now().Unix()
	domainName := func(i int) string { return fmt.Sprintf("bench%07d.example.com", i) }

	var results []proofResult
	inserted := 0
	for _, size := range sizes {
		for ; inserted < size; inserted++ {
			cert, err := types.NewCertificate(domainName(inserted), pub, types.Algorithm_ALGORITHM_ED25519, validFrom)
			if err != nil {
				return nil, err
			}
			if err := smt.SetDomain(domainName(inserted), &types.DomainState{Certificate: cert}); err != nil {
				return nil, err
			}
		}
		root, err := smt.Root()
		if err != nil {
			return nil, err
		}

		res := proofResult{Domains: size, Samples: samples}

		// Inclusion proofs for random present domains.
		var totalBytes, totalSiblings int
		var totalVerify time.Duration
		for range samples {
			domain := domainName(rand.IntN(size))
			proof, err := smt.ProveDomain(domain)
			if err != nil {
				return nil, err
			}
			raw, err := proof.MarshalBinary()
			if err != nil {
				return nil, err
			}
			totalBytes += len(raw)
			res.MaxProofBytes = max(res.MaxProofBytes, len(raw))
			totalSiblings += len(proof.Siblings)

			start := time.Now()
			if _, present, err := state.VerifyDomainProof(root, domain, proof); err != nil || !present {
				return nil, fmt.Errorf("inclusion proof for %s did not verify: present=%v err=%v", domain, present, err)
			}
			totalVerify += time.Since(start)
		}
		res.AvgProofBytes = float64(totalBytes) / float64(samples)
		res.AvgSiblings = float64(totalSiblings) / float64(samples)
		res.AvgVerifyUs = float64(totalVerify.Microseconds()) / float64(samples)

		// Non-inclusion proofs for absent domains.
		const nonIncl = 50
		res.NonInclSamplesChecked = nonIncl
		totalBytes, totalVerify = 0, 0
		for i := range nonIncl {
			domain := fmt.Sprintf("absent%07d.example.net", i)
			proof, err := smt.ProveDomain(domain)
			if err != nil {
				return nil, err
			}
			raw, err := proof.MarshalBinary()
			if err != nil {
				return nil, err
			}
			totalBytes += len(raw)

			start := time.Now()
			if _, present, err := state.VerifyDomainProof(root, domain, proof); err != nil || present {
				return nil, fmt.Errorf("non-inclusion proof for %s did not verify: present=%v err=%v", domain, present, err)
			}
			totalVerify += time.Since(start)
		}
		res.NonInclProofBytes = float64(totalBytes) / float64(nonIncl)
		res.NonInclAvgVerifyUs = float64(totalVerify.Microseconds()) / float64(nonIncl)

		results = append(results, res)
		fmt.Fprintf(os.Stderr, "proof: N=%d, avg %.0f B (%.1f siblings), verify %.1f µs\n",
			size, res.AvgProofBytes, res.AvgSiblings, res.AvgVerifyUs)
	}
	return results, nil
}
