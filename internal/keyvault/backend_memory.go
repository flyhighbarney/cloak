package keyvault

import (
	"sort"
	"sync"
)

// memoryBackend is the default backend used until main() swaps in the
// OS-native store, and the backend of choice for tests. Values live in
// process memory only; a restart clears them.
type memoryBackend struct {
	mu   sync.Mutex
	data map[string]string
}

func newMemoryBackend() *memoryBackend {
	return &memoryBackend{data: make(map[string]string)}
}

func (m *memoryBackend) Name() string { return "memory" }

func (m *memoryBackend) Set(provider, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[provider] = key
	return nil
}

func (m *memoryBackend) Get(provider string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[provider]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}

func (m *memoryBackend) Delete(provider string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.data[provider]; !ok {
		return ErrNotFound
	}
	delete(m.data, provider)
	return nil
}

func (m *memoryBackend) List() ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.data))
	for k := range m.data {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}
