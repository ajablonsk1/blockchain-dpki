package state

import (
	"bytes"
	"encoding/binary"
	"errors"
	"slices"

	"github.com/ajablonsk1/blockchain-dpki/internal/crypto"
)

// TreeDepth is the fixed depth of the Sparse Merkle Tree. Keys are SHA-256
// digests (256 bits), so every key addresses a leaf at depth 256. A fixed depth
// is what makes the structure deterministic regardless of insertion order: the
// position of a leaf depends only on its key, never on history.
const TreeDepth = 256

// KeySize is the required length in bytes of every SMT key (SHA-256 output).
const KeySize = 32

// Domain-separation tags. Prefixing leaf and internal preimages with distinct
// bytes makes it impossible for a leaf hash to be reinterpreted as an internal
// node hash (or vice versa), closing a class of second-preimage ambiguities.
const (
	leafPrefix     = 0x00
	internalPrefix = 0x01
)

// Node-store and value-store key prefixes, kept disjoint within one KVStore.
const (
	nodePrefix  = 'n'
	valuePrefix = 'v'
)

var ErrInvalidKeyLength = errors.New("state: key must be 32 bytes")

// defaultHashes[d] is the hash of a completely empty subtree rooted at depth d.
// defaultHashes[TreeDepth] is the empty-leaf placeholder (32 zero bytes); every
// shallower level is the hash of two empty children below it. Precomputing these
// lets the tree represent 2^256 leaves while storing only the populated paths:
// an absent sibling is, by definition, the default hash for its depth.
var defaultHashes [][]byte

func init() {
	defaultHashes = make([][]byte, TreeDepth+1)
	defaultHashes[TreeDepth] = make([]byte, 32) // empty leaf placeholder
	for d := TreeDepth - 1; d >= 0; d-- {
		defaultHashes[d] = internalHash(defaultHashes[d+1], defaultHashes[d+1])
	}
}

// leafHash returns the tree hash of a present leaf value.
func leafHash(value []byte) []byte {
	return crypto.Hash(slices.Concat([]byte{leafPrefix}, value))
}

// internalHash returns the hash of an internal node with the given children.
func internalHash(left, right []byte) []byte {
	return crypto.Hash(slices.Concat([]byte{internalPrefix}, left, right))
}

// SMT is a Sparse Merkle Tree persisted on a KVStore. The zero value is not
// usable; construct one with NewSMT. SMT is safe for concurrent use only insofar
// as its KVStore is; callers performing read-modify-write sequences (Set/Delete)
// must serialize them externally, which the consensus layer does naturally by
// applying transactions one block at a time.
type SMT struct {
	kv KVStore
}

// NewSMT returns an SMT backed by kv. An empty store represents the empty tree,
// whose root is defaultHashes[0].
func NewSMT(kv KVStore) *SMT {
	return &SMT{kv: kv}
}

// Root returns the current 32-byte root hash. For an empty tree it is the
// default hash at depth 0.
func (s *SMT) Root() ([]byte, error) {
	return s.getNode(0, make([]byte, KeySize))
}

// Get returns the value stored under key and whether it is present. A missing
// key is not an error; it returns (nil, false, nil).
func (s *SMT) Get(key []byte) ([]byte, bool, error) {
	if len(key) != KeySize {
		return nil, false, ErrInvalidKeyLength
	}

	v, err := s.kv.Get(valueKey(key))
	if errors.Is(err, ErrKeyNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}

	return v, true, nil
}

// Has reports whether key is present.
func (s *SMT) Has(key []byte) (bool, error) {
	_, ok, err := s.Get(key)
	return ok, err
}

// Set stores value under key and updates the tree so that the new root commits
// to it. key must be exactly KeySize bytes. value must be non-empty: the proof
// encoding reserves a nil/empty value to mean non-inclusion (see Proof), so an
// empty value cannot be distinguished from an absent key. The domain layer
// always stores non-empty protobuf encodings, so this is not a restriction in
// practice; use Delete to remove a key.
func (s *SMT) Set(key, value []byte) error {
	if len(key) != KeySize {
		return ErrInvalidKeyLength
	}

	if err := s.kv.Set(valueKey(key), value); err != nil {
		return err
	}

	return s.updatePath(key, leafHash(value))
}

// Delete removes key from the tree. Deleting an absent key is a no-op that
// leaves the root unchanged.
func (s *SMT) Delete(key []byte) error {
	if len(key) != KeySize {
		return ErrInvalidKeyLength
	}

	if err := s.kv.Delete(valueKey(key)); err != nil {
		return err
	}

	// Setting the leaf back to the empty placeholder collapses the path to
	// default hashes, restoring the exact root the tree would have had if the
	// key had never been inserted.
	return s.updatePath(key, defaultHashes[TreeDepth])
}

// updatePath rewrites the single root-to-leaf path for key, setting its leaf to
// leaf and recomputing every ancestor from the leaf up to the root. Exactly
// TreeDepth+1 nodes are touched. Nodes whose hash collapses to the default for
// their depth are deleted rather than stored, which keeps the persisted node set
// canonical and the root independent of insertion order.
func (s *SMT) updatePath(key, leaf []byte) error {
	cur := leaf

	for d := TreeDepth; d >= 1; d-- {
		if err := s.putNode(d, prefixMask(key, d), cur); err != nil {
			return err
		}

		sibHash, err := s.getNode(d, siblingMask(key, d))
		if err != nil {
			return err
		}

		// Bit d-1 selects which child lies on the path: 0 = left, 1 = right.
		if bitAt(key, d-1) {
			cur = internalHash(sibHash, cur)
		} else {
			cur = internalHash(cur, sibHash)
		}
	}

	// Persist the root at depth 0 (path mask is all zeros).
	return s.putNode(0, make([]byte, KeySize), cur)
}

// getNode returns the stored hash of the node at depth d on the given masked
// path, or the default hash for that depth if the node is absent.
func (s *SMT) getNode(depth int, masked []byte) ([]byte, error) {
	v, err := s.kv.Get(nodeKey(depth, masked))
	if errors.Is(err, ErrKeyNotFound) {
		return append([]byte(nil), defaultHashes[depth]...), nil
	}
	if err != nil {
		return nil, err
	}

	return v, nil
}

// putNode stores hash for the node at depth d on the masked path, or deletes the
// entry when hash equals the default for that depth.
func (s *SMT) putNode(depth int, masked, hash []byte) error {
	if bytes.Equal(hash, defaultHashes[depth]) {
		return s.kv.Delete(nodeKey(depth, masked))
	}
	return s.kv.Set(nodeKey(depth, masked), hash)
}

// --- key encoding & bit helpers ---------------------------------------------

// valueKey is the KVStore key under which the raw value for an SMT key is stored.
func valueKey(key []byte) []byte {
	return append([]byte{valuePrefix}, key...)
}

// nodeKey is the KVStore key for a tree node, identified by its depth and the
// masked key prefix that addresses it. Including the depth disambiguates nodes
// whose prefixes share bytes but differ in significant bit-length.
func nodeKey(depth int, masked []byte) []byte {
	out := make([]byte, 1+2+KeySize)
	out[0] = nodePrefix
	binary.BigEndian.PutUint16(out[1:3], uint16(depth))
	copy(out[3:], masked)
	return out
}

// prefixMask returns a 32-byte copy of key with all but the top `bits` bits
// cleared. It addresses the node at depth `bits` on key's path.
func prefixMask(key []byte, bits int) []byte {
	out := make([]byte, KeySize)
	full := bits / 8
	copy(out[:full], key[:full])
	if rem := bits % 8; rem != 0 {
		out[full] = key[full] & (0xFF << (8 - rem))
	}
	return out
}

// siblingMask returns the masked path of the sibling, at depth d, of the node on
// key's path. The sibling shares key's top d-1 bits and flips bit d-1.
func siblingMask(key []byte, d int) []byte {
	m := prefixMask(key, d-1)
	if !bitAt(key, d-1) {
		setBit(m, d-1) // on-path bit is 0, so the sibling's bit is 1
	}
	return m
}

// bitAt reports whether bit i (0 = most significant bit of byte 0) is set.
func bitAt(b []byte, i int) bool {
	return b[i>>3]&(0x80>>(uint(i)&7)) != 0
}

// setBit sets bit i (0 = most significant bit of byte 0).
func setBit(b []byte, i int) {
	b[i>>3] |= 0x80 >> (uint(i) & 7)
}
