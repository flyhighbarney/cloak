// Package keyvault stores AI-provider API keys in the OS-native credential
// store (Windows Credential Manager, macOS Keychain, Linux Secret Service).
//
// Design constraints:
//
//   - Keys never touch disk in plaintext. The OS owns the secret lifecycle.
//   - The package exposes provider-scoped operations only. The dashboard
//     receives presence + last-4 of a stored key, never the value.
//   - A pluggable Backend lets tests and CI environments run against an
//     in-memory fake without a real keyring service.
//
// The vault is intentionally per-user, per-machine. There is no import,
// export, or sync. If the user wants their keys on another machine they
// re-paste them there — this is the point of using the OS keyring.
package keyvault

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

// Service is the well-known service name used across all backends.
// Do not change without a migration story: existing keyring entries will
// be orphaned.
const Service = "cloakline"

// ErrNotFound is returned by Get and Delete when no key is stored for
// the requested provider. Callers should treat this as an ordinary
// "unset" state, not an error.
var ErrNotFound = errors.New("keyvault: key not found for provider")

// Backend is the storage contract. Implementations must be safe for
// concurrent use.
type Backend interface {
	Set(provider, key string) error
	Get(provider string) (string, error) // returns ErrNotFound when absent
	Delete(provider string) error         // returns ErrNotFound when absent
	List() ([]string, error)              // provider IDs only, sorted
	Name() string                         // for diagnostics, e.g. "wincred", "memory"
}

var (
	mu      sync.RWMutex
	backend Backend = newMemoryBackend()
)

// SetBackend swaps the active backend. Intended for tests and for the
// process-level wiring in main() that selects the OS-native store at
// startup. Passing nil resets to the in-memory fallback.
func SetBackend(b Backend) {
	mu.Lock()
	defer mu.Unlock()
	if b == nil {
		backend = newMemoryBackend()
		return
	}
	backend = b
}

// Install activates the OS-native backend for the current platform if
// one is available. On Windows this switches to DPAPI-encrypted files
// under %LOCALAPPDATA%\cloakline\keys\. On other platforms it is a no-op
// today and the in-memory backend remains active.
//
// Returns the name of the backend that is now active, plus any error
// encountered while attempting to install the native backend. An error
// leaves the memory backend in place — callers can log and continue.
func Install() (string, error) {
	b, err := newOSBackend()
	if err != nil {
		return ActiveBackendName(), err
	}
	if b != nil {
		SetBackend(b)
	}
	return ActiveBackendName(), nil
}

// ActiveBackendName reports which backend is currently installed.
// Used by the dashboard footer and /admin diagnostics.
func ActiveBackendName() string {
	mu.RLock()
	defer mu.RUnlock()
	return backend.Name()
}

// Set stores the key for a provider. The provider ID is normalised to
// lowercase; whitespace around the key is trimmed. Empty keys are
// rejected to avoid silently overwriting a real key with nothing.
func Set(provider, key string) error {
	p, err := normalizeProvider(provider)
	if err != nil {
		return err
	}
	k := strings.TrimSpace(key)
	if k == "" {
		return errors.New("keyvault: refusing to store empty key")
	}
	mu.RLock()
	b := backend
	mu.RUnlock()
	return b.Set(p, k)
}

// Get returns the stored key for a provider, or ErrNotFound.
func Get(provider string) (string, error) {
	p, err := normalizeProvider(provider)
	if err != nil {
		return "", err
	}
	mu.RLock()
	b := backend
	mu.RUnlock()
	return b.Get(p)
}

// Delete removes the stored key for a provider. Absence is reported as
// ErrNotFound so callers can distinguish "we cleared it" from "there
// was nothing to clear".
func Delete(provider string) error {
	p, err := normalizeProvider(provider)
	if err != nil {
		return err
	}
	mu.RLock()
	b := backend
	mu.RUnlock()
	return b.Delete(p)
}

// List returns the provider IDs with keys currently stored, sorted.
// Values are never returned.
func List() ([]string, error) {
	mu.RLock()
	b := backend
	mu.RUnlock()
	return b.List()
}

// Mask returns a UI-safe representation of a stored key. It never
// reveals more than the last four characters. Used by the dashboard.
func Mask(key string) string {
	k := strings.TrimSpace(key)
	if k == "" {
		return ""
	}
	if len(k) <= 4 {
		return strings.Repeat("•", len(k))
	}
	return strings.Repeat("•", 8) + k[len(k)-4:]
}

// normalizeProvider enforces a lowercase ASCII slug so callers can use
// mixed case freely without producing duplicate keyring entries.
func normalizeProvider(provider string) (string, error) {
	p := strings.ToLower(strings.TrimSpace(provider))
	if p == "" {
		return "", errors.New("keyvault: provider ID is required")
	}
	for _, r := range p {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_'
		if !ok {
			return "", fmt.Errorf("keyvault: provider ID %q has invalid character %q", provider, r)
		}
	}
	return p, nil
}
