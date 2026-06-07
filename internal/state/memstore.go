package state

import "sync"

// MemoryStore is an in-memory KVStore backed by a map. It is safe for
// concurrent use and copies all keys and values on the way in and out so that
// callers cannot mutate stored data through retained slices. It is intended for
// tests and for running a node without persistence
type MemoryStore struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{data: make(map[string][]byte)}
}

// Get returns a copy of the value stored under key, or ErrKeyNotFound.
func (m *MemoryStore) Get(key []byte) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	v, ok := m.data[string(key)]
	if !ok {
		return nil, ErrKeyNotFound
	}

	return append([]byte(nil), v...), nil
}

// Set stores a copy of value under a copy of key.
func (m *MemoryStore) Set(key, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.data[string(key)] = append([]byte(nil), value...)
	return nil
}

// Delete removes key. Deleting an absent key is a no-op.
func (m *MemoryStore) Delete(key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.data, string(key))
	return nil
}

// Close releases resources. For MemoryStore it is a no-op.
func (m *MemoryStore) Close() error { return nil }

// Len reports the number of stored key/value pairs. It is a test and
// diagnostics helper, not part of the KVStore interface.
func (m *MemoryStore) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.data)
}
