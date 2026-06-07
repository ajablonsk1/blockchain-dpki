package state

import "errors"

var ErrKeyNotFound = errors.New("state: key not found")

// KVStore is the minimal key/value backend the SMT persists itself on. It is a
// deliberately small interface so that the in-memory implementation used in
// tests can be swapped for an embedded store (e.g. BadgerDB)
//
// Implementations MUST treat keys and values as opaque byte slices and MUST NOT
// retain references to the slices passed in; the SMT reuses buffers.
type KVStore interface {
	// Get returns the value stored under key, or ErrKeyNotFound if absent.
	Get(key []byte) ([]byte, error)
	// Set stores value under key, overwriting any existing value.
	Set(key, value []byte) error
	// Delete removes key. Deleting an absent key is not an error.
	Delete(key []byte) error
	// Close releases backend resources.
	Close() error
}
