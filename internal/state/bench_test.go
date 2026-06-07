package state

import "testing"

// prefilledSMT returns an SMT preloaded with n key/value pairs.
func prefilledSMT(n int) *SMT {
	s := newSMT()
	for i := range n {
		_ = s.Set(testKey(i), testVal(i))
	}
	return s
}

// BenchmarkSMT_Set measures the cost of a single update (one root-to-leaf path
// rewrite, ~256 hashes) against an already-populated tree.
func BenchmarkSMT_Set(b *testing.B) {
	s := prefilledSMT(10_000)
	i := 0
	for b.Loop() {
		_ = s.Set(testKey(1_000_000+i), testVal(i))
		i++
	}
}

// BenchmarkSMT_Prove measures proof generation against a populated tree.
func BenchmarkSMT_Prove(b *testing.B) {
	s := prefilledSMT(10_000)
	key := testKey(42)
	for b.Loop() {
		if _, err := s.Prove(key); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVerifyProof measures the light-client verification cost and reports
// the proof size, the key evaluation metric for the CRL/OCSP comparison.
func BenchmarkVerifyProof(b *testing.B) {
	s := prefilledSMT(10_000)
	root, _ := s.Root()
	p, _ := s.Prove(testKey(42))

	for b.Loop() {
		if !VerifyProof(root, p) {
			b.Fatal("verification failed")
		}
	}

	size := len(p.Key) + len(p.Value) + len(p.Bitmap)
	for _, sib := range p.Siblings {
		size += len(sib)
	}
	b.ReportMetric(float64(size), "proof-bytes")
	b.ReportMetric(float64(len(p.Siblings)), "siblings")
}
