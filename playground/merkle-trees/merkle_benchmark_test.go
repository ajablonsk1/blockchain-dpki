package merkle

import (
	"fmt"
	"math/rand"
	"testing"
)

func BenchmarkTreeBuild100(b *testing.B)  { benchBuild(b, 100) }
func BenchmarkTreeBuild1k(b *testing.B)   { benchBuild(b, 1_000) }
func BenchmarkTreeBuild10K(b *testing.B)  { benchBuild(b, 10_000) }
func BenchmarkTreeBuild100K(b *testing.B) { benchBuild(b, 100_000) }

func BenchmarkProofGenerate100(b *testing.B)  { benchProof(b, 100) }
func BenchmarkProofGenerate1k(b *testing.B)   { benchProof(b, 1_000) }
func BenchmarkProofGenerate10K(b *testing.B)  { benchProof(b, 10_000) }
func BenchmarkProofGenerate100K(b *testing.B) { benchProof(b, 100_000) }

func BenchmarkProofVerify100(b *testing.B)  { benchVerify(b, 100) }
func BenchmarkProofVerify1k(b *testing.B)   { benchVerify(b, 1_000) }
func BenchmarkProofVerify10K(b *testing.B)  { benchVerify(b, 10_000) }
func BenchmarkProofVerify100K(b *testing.B) { benchVerify(b, 100_000) }

func TestProofSize(t *testing.T) {
	sizes := []int{100, 1_000, 10_000, 100_000}
	for _, n := range sizes {
		certs := make([][]byte, n)
		for i := range n {
			certs[i] = fmt.Appendf(nil, "example %d", i)
		}
		tree := NewTree(certs)
		proof, _ := tree.Proof(0)

		totalBytes := 0
		for _, p := range proof {
			totalBytes += len(p.Hash) + 1 // hash + IsRight bool
		}
		fmt.Printf("n=%6d → proof elements: %d, proof size: %d bytes\n", n, len(proof), totalBytes)
	}
}

func benchBuild(b *testing.B, certsNum int) {
	certs := make([][]byte, certsNum)
	for i := range certsNum {
		certs[i] = fmt.Appendf(nil, "example %d", i)
	}

	for b.Loop() {
		_ = NewTree(certs)
	}
}

func benchProof(b *testing.B, certsNum int) {
	certs := make([][]byte, certsNum)
	for i := range certsNum {
		certs[i] = fmt.Appendf(nil, "example %d", i)
	}
	tree := NewTree(certs)

	for b.Loop() {
		_, _ = tree.Proof(rand.Intn(certsNum))
	}
}

func benchVerify(b *testing.B, certsNum int) {
	certs := make([][]byte, certsNum)
	for i := range certsNum {
		certs[i] = fmt.Appendf(nil, "example %d", i)
	}
	tree := NewTree(certs)
	index := rand.Intn(certsNum)
	proof, _ := tree.Proof(index)

	for b.Loop() {
		_ = Verify(tree.RootHash(), fmt.Appendf(nil, "example %d", index), index, proof)
	}
}
