// Package prefs stores per-kind DLP action overrides that the user
// sets through the admin dashboard.
//
// The prefs file itself does not contain credentials. But per the
// design directive that "anything cloakline stores is AES-encrypted,"
// this package encrypts the JSON payload with a per-machine key.
//
// Layout:
//
//   %LOCALAPPDATA%\cloakline\prefs.bin  (Windows)
//   $XDG_CONFIG_HOME/cloakline/prefs.bin  (Linux/macOS)
//
// The 32-byte AES key lives in the same directory as prefs.bin under
// a companion filename. On Windows the key file is DPAPI-wrapped
// (only the current user can unwrap). On non-Windows the key file is
// 0o600 — good enough for a single-developer machine, but weaker
// than DPAPI. A follow-up (T-KEYVAULT-KEYRING for macOS/Linux) will
// upgrade this.
package prefs

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"cloakline/internal/crypto/aesbox"
)

// Prefs is the on-disk shape of the prefs file (after decryption).
type Prefs struct {
	Kinds                   map[string]KindPref `json:"kinds,omitempty"`
	SessionOptoutTTLSeconds int                 `json:"session_optout_ttl_seconds,omitempty"`
}

// KindPref overrides the tiered default for a single detection kind.
type KindPref struct {
	// Action is one of "allow" | "warn" | "redact" | "block" |
	// "redact_one_way" | "flag". Empty = defer to tier default.
	Action string `json:"action,omitempty"`
}

// Store reads and writes prefs.bin.
//
// Concurrency: the store is safe to call from multiple goroutines. An
// RWMutex protects the in-memory cache; Load returns a snapshot from
// the cache when it's fresh, otherwise it re-reads from disk. Save
// invalidates the cache so the next Load re-populates. This turns the
// per-DLP-finding hot-path lookup into a lock-hold + map read, not a
// file read + AES decrypt.
type Store struct {
	dir      string
	keyFile  string
	dataFile string

	mu        sync.RWMutex
	cachedKey []byte // AES key; zeroized on Close.
	// cached holds the last-known prefs value from disk. valid==false
	// means "re-read on next Load". Guarded by mu.
	cached      Prefs
	cachedValid bool
}

// Open creates the store, ensuring the storage directory exists and
// materialising the AES key on first use. Returns a store even if
// prefs.bin is missing — the empty state is valid.
func Open() (*Store, error) {
	dir, err := storageDir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("prefs: mkdir %s: %w", dir, err)
	}
	s := &Store{
		dir:      dir,
		keyFile:  filepath.Join(dir, "prefs.key"),
		dataFile: filepath.Join(dir, "prefs.bin"),
	}
	key, err := s.loadOrCreateKey()
	if err != nil {
		return nil, err
	}
	s.cachedKey = key
	return s, nil
}

// Close zeroizes the in-memory AES key. Safe to call multiple times.
func (s *Store) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cachedKey != nil {
		aesbox.Zeroize(s.cachedKey)
		s.cachedKey = nil
	}
	s.cached = Prefs{}
	s.cachedValid = false
}

// Load returns the current prefs. Uses the in-memory cache when it's
// fresh; only reads and decrypts the file on a cache miss. An absent
// or empty file returns an empty Prefs value with no error.
func (s *Store) Load() (Prefs, error) {
	// Fast path — cache hit.
	s.mu.RLock()
	if s.cachedValid {
		p := s.cached
		s.mu.RUnlock()
		return p, nil
	}
	s.mu.RUnlock()

	// Slow path — re-read. Take the write lock and double-check
	// in case another goroutine populated while we were waiting.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cachedValid {
		return s.cached, nil
	}
	p, err := s.readFromDiskLocked()
	if err != nil {
		return Prefs{}, err
	}
	s.cached = p
	s.cachedValid = true
	return p, nil
}

// readFromDiskLocked performs the actual file read + AES decrypt.
// Caller MUST hold s.mu (write).
func (s *Store) readFromDiskLocked() (Prefs, error) {
	raw, err := os.ReadFile(s.dataFile)
	if errors.Is(err, os.ErrNotExist) {
		return Prefs{}, nil
	}
	if err != nil {
		return Prefs{}, fmt.Errorf("prefs: read %s: %w", s.dataFile, err)
	}
	if len(raw) == 0 {
		return Prefs{}, nil
	}
	plain, err := aesbox.Open(s.cachedKey, raw, []byte("cloakline/prefs/v1"))
	if err != nil {
		return Prefs{}, fmt.Errorf("prefs: decrypt: %w", err)
	}
	defer aesbox.Zeroize(plain)

	var p Prefs
	if err := json.Unmarshal(plain, &p); err != nil {
		return Prefs{}, fmt.Errorf("prefs: parse: %w", err)
	}
	return p, nil
}

// Save encrypts and writes prefs atomically (write-temp + rename),
// then updates the cache under the same lock so readers see a
// consistent view — no window where the on-disk file has one value
// and the cache still has the old one.
func (s *Store) Save(p Prefs) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	plain, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("prefs: marshal: %w", err)
	}
	defer aesbox.Zeroize(plain)

	box, err := aesbox.Seal(s.cachedKey, plain, []byte("cloakline/prefs/v1"))
	if err != nil {
		return fmt.Errorf("prefs: encrypt: %w", err)
	}
	tmp := s.dataFile + ".tmp"
	if err := os.WriteFile(tmp, box, 0o600); err != nil {
		return fmt.Errorf("prefs: write temp: %w", err)
	}
	if err := os.Rename(tmp, s.dataFile); err != nil {
		return fmt.Errorf("prefs: rename: %w", err)
	}
	s.cached = p
	s.cachedValid = true
	return nil
}

// ActionForKind is the runtime lookup used by the DLP path. Returns
// ("", false) when no explicit override is set for the kind, letting
// the caller fall back to the tiered default. Hot-path: hits the
// in-memory cache after the first call.
func (s *Store) ActionForKind(kind string) (string, bool) {
	p, err := s.Load()
	if err != nil {
		return "", false
	}
	if kp, ok := p.Kinds[kind]; ok && kp.Action != "" {
		return kp.Action, true
	}
	return "", false
}

// storageDir returns the platform-appropriate prefs directory.
func storageDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("prefs: locate config dir: %w", err)
	}
	return filepath.Join(base, "cloakline"), nil
}

// loadOrCreateKey reads the AES key from disk, or generates and
// persists a new one. Platform-specific wrapping happens in
// wrapKeyForDisk / unwrapKeyFromDisk (see the *_windows.go /
// *_other.go files).
func (s *Store) loadOrCreateKey() ([]byte, error) {
	if raw, err := os.ReadFile(s.keyFile); err == nil {
		key, err := unwrapKeyFromDisk(raw)
		if err != nil {
			return nil, fmt.Errorf("prefs: unwrap key: %w", err)
		}
		if len(key) != aesbox.KeySize {
			return nil, fmt.Errorf("prefs: key length %d, want %d", len(key), aesbox.KeySize)
		}
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("prefs: read key file: %w", err)
	}

	// First run — mint a new key.
	key, err := aesbox.NewKey()
	if err != nil {
		return nil, err
	}
	wrapped, err := wrapKeyForDisk(key)
	if err != nil {
		aesbox.Zeroize(key)
		return nil, fmt.Errorf("prefs: wrap key: %w", err)
	}
	if err := os.WriteFile(s.keyFile, wrapped, 0o600); err != nil {
		aesbox.Zeroize(key)
		return nil, fmt.Errorf("prefs: write key: %w", err)
	}
	return key, nil
}
