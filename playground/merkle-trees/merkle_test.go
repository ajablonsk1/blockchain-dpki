package merkle

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBasicTree(t *testing.T) {
	data := [][]byte{[]byte("cert1"), []byte("cert2"), []byte("cert3"), []byte("cert4")}
	tree := NewTree(data)

	assert.NotNil(t, tree.RootHash(), "root shouldn't be nil")

	tree2 := NewTree(data)
	assert.True(t, bytes.Equal(tree.RootHash(), tree2.RootHash()), "root hashes should be equal")

	data2 := [][]byte{[]byte("CHANGED"), []byte("cert2"), []byte("cert3"), []byte("cert4")}
	tree3 := NewTree(data2)
	assert.False(t, bytes.Equal(tree.RootHash(), tree3.RootHash()), "root hashes should't be equal")
}

func TestProofAndVerify(t *testing.T) {
	data := [][]byte{[]byte("cert1"), []byte("cert2"), []byte("cert3"), []byte("cert4")}
	tree := NewTree(data)

	for i, d := range data {
		proof, _ := tree.Proof(i)
		assert.True(t, Verify(tree.RootHash(), d, i, proof), "proof should verify")
	}

	proof, _ := tree.Proof(0)
	assert.False(t, Verify(tree.RootHash(), []byte("fake"), 0, proof), "proof should verify")
}

func TestOddNumberOfLeaves(t *testing.T) {
	data := [][]byte{[]byte("cert1"), []byte("cert2"), []byte("cert3")}
	tree := NewTree(data)
	for i, d := range data {
		proof, _ := tree.Proof(i)
		assert.True(t, Verify(tree.RootHash(), d, i, proof))
	}
}

func TestSingleLeaf(t *testing.T) {
	data := [][]byte{[]byte("only-cert")}
	tree := NewTree(data)
	proof, _ := tree.Proof(0)
	assert.True(t, Verify(tree.RootHash(), data[0], 0, proof))
}
