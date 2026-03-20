package merkle

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"slices"
)

type MerkleTree struct {
	Nodes        [][]byte // indexed from 1; index 0 is not used
	LeafCapacity int
	LeafCount    int
}

func NewTree(certs [][]byte) *MerkleTree {
	if len(certs) == 0 {
		return nil
	}

	leafCapacity := 1
	for leafCapacity < len(certs) {
		leafCapacity *= 2
	}

	nodes := make([][]byte, 2*leafCapacity)

	for i := leafCapacity; i < 2*leafCapacity; i++ {
		var h [32]byte
		if i < leafCapacity+len(certs) {
			h = sha256.Sum256(certs[i-leafCapacity])
		} else {
			h = sha256.Sum256([]byte{})
		}
		nodes[i] = h[:]
	}

	for i := leafCapacity - 1; i > 0; i-- {
		h := sha256.Sum256(slices.Concat(nodes[2*i], nodes[2*i+1]))
		nodes[i] = h[:]
	}

	return &MerkleTree{nodes, leafCapacity, len(certs)}
}

func (t *MerkleTree) RootHash() []byte {
	return t.Nodes[1]
}

func (t *MerkleTree) Proof(index int) ([]ProofElement, error) {
	if index < 0 || index >= t.LeafCount {
		return nil, errors.New("merkle tree: index out of leaf range")
	}

	proof := []ProofElement{}
	pos := t.LeafCapacity + index
	for pos > 1 {
		siblingPos := pos ^ 1
		proof = append(proof, ProofElement{t.Nodes[siblingPos], siblingPos%2 != 0})
		pos /= 2
	}

	return proof, nil
}

func Verify(root []byte, data []byte, index int, proof []ProofElement) bool {
	h := sha256.Sum256(data)
	currentHash := h[:]
	for _, proofElement := range proof {
		var h [32]byte
		if proofElement.IsRight {
			h = sha256.Sum256(slices.Concat(currentHash, proofElement.Hash))
		} else {
			h = sha256.Sum256(slices.Concat(proofElement.Hash, currentHash))
		}
		currentHash = h[:]
	}

	return bytes.Equal(root, currentHash)
}

type ProofElement struct {
	Hash    []byte
	IsRight bool
}
