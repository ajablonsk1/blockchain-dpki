package app

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"
)

// makeRegisterBatch builds n signed RegisterTx for distinct domains. Distinct
// domains means the order of application does not change the final state, which
// lets the determinism test also assert order-independence of the app hash.
func makeRegisterBatch(t *testing.T, n int) [][]byte {
	t.Helper()
	txs := make([][]byte, n)
	for i := range n {
		priv, pub := keypair(t)
		domain := fmt.Sprintf("domain-%d.example.com", i)
		txs[i] = signedRegister(t, priv, pub, domain)
	}
	return txs
}

// TestDeterministic_AppHash applies the same 100 transactions to two independent
// application instances and requires byte-identical app hashes — the core
// invariant a blockchain depends on.
func TestDeterministic_AppHash(t *testing.T) {
	txs := makeRegisterBatch(t, 100)

	app1 := newTestApp(t)
	app2 := newTestApp(t)

	h1 := finalize(t, app1, 1, txs...).AppHash
	h2 := finalize(t, app2, 1, txs...).AppHash

	if !bytes.Equal(h1, h2) {
		t.Fatalf("app hashes differ for identical input:\n app1 = %x\n app2 = %x", h1, h2)
	}
}

// TestDeterministic_OrderIndependent applies the same set of transactions in two
// different orders and still requires identical app hashes. Because every
// transaction targets a distinct domain, both orders represent the same final
// state, and the SMT commits it to the same root regardless of insertion order.
func TestDeterministic_OrderIndependent(t *testing.T) {
	txs := makeRegisterBatch(t, 50)

	shuffled := make([][]byte, len(txs))
	copy(shuffled, txs)
	rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })

	app1 := newTestApp(t)
	app2 := newTestApp(t)

	h1 := finalize(t, app1, 1, txs...).AppHash
	h2 := finalize(t, app2, 1, shuffled...).AppHash

	if !bytes.Equal(h1, h2) {
		t.Fatalf("app hash depends on transaction order:\n ordered  = %x\n shuffled = %x", h1, h2)
	}
}
