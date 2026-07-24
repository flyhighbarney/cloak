// Package auth resolves virtual API keys (sk-gw-*) to typed Principals.
// See docs/threat-model.md T4 for the model.
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"policyd/internal/api"
)

// Store is an in-memory map of key-hash → Principal.
type Store struct {
	mu      sync.RWMutex
	byHash  map[string]api.Principal
}

// NewStore constructs an empty store.
func NewStore() *Store {
	return &Store{byHash: make(map[string]api.Principal)}
}

// Add registers a Principal by plaintext virtual key. The plaintext is
// hashed immediately; the plaintext is not retained.
func (s *Store) Add(plaintextKey string, p api.Principal) error {
	if !strings.HasPrefix(plaintextKey, "sk-gw-") {
		return fmt.Errorf("%w: virtual keys must have sk-gw- prefix", api.ErrConfigInvalid)
	}
	h := hashKey(plaintextKey)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byHash[h] = p
	return nil
}

// Resolve returns the Principal for a plaintext key, or an error.
// Comparison is constant-time via the hash lookup.
func (s *Store) Resolve(plaintextKey string, now time.Time) (api.Principal, error) {
	if plaintextKey == "" {
		return api.Principal{}, fmt.Errorf("%w: empty key", api.ErrAuthFailed)
	}
	if !strings.HasPrefix(plaintextKey, "sk-gw-") {
		return api.Principal{}, fmt.Errorf("%w: not a virtual key", api.ErrAuthFailed)
	}
	h := hashKey(plaintextKey)

	s.mu.RLock()
	// Iterate to make comparison constant-time regardless of hit/miss.
	var found *api.Principal
	for k, p := range s.byHash {
		if subtle.ConstantTimeCompare([]byte(k), []byte(h)) == 1 {
			// Copy to avoid holding the lock through the caller.
			cp := p
			found = &cp
		}
	}
	s.mu.RUnlock()

	if found == nil {
		return api.Principal{}, fmt.Errorf("%w: unknown key", api.ErrAuthFailed)
	}
	if found.Expired(now) {
		return api.Principal{}, fmt.Errorf("%w: expired", api.ErrAuthFailed)
	}
	return *found, nil
}

// Count returns the number of registered principals. For telemetry.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byHash)
}

func hashKey(k string) string {
	sum := sha256.Sum256([]byte(k))
	return hex.EncodeToString(sum[:])
}

// ExtractBearer pulls the bearer token from an Authorization header value.
func ExtractBearer(authHeader string) string {
	const prefix = "Bearer "
	if len(authHeader) < len(prefix) {
		return ""
	}
	if !strings.EqualFold(authHeader[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(authHeader[len(prefix):])
}
