//go:build darwin

package keyvault

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// darwinBackend stores each provider's key as a generic password in the
// user's login keychain via /usr/bin/security. Keychain items are
// encrypted at rest, unlockable only by the same user with keychain
// access, and appear in Keychain Access.app under the "cloakline"
// service name.
//
// The `security` CLI ships on every macOS install, so no external
// dependency and no CGO to Security.framework is needed.
//
// List() cannot cleanly enumerate items by service name via `security`
// without triggering a keychain-unlock prompt, so we keep a plaintext
// index of provider IDs (no secrets in it) alongside — same approach
// used by other keychain-backed tools like `pass` for its GPG keys.
type darwinBackend struct {
	mu        sync.Mutex
	indexPath string
}

const darwinKeychainService = "cloakline"

func newOSBackend() (Backend, error) {
	if _, err := exec.LookPath("security"); err != nil {
		return nil, fmt.Errorf("keyvault: /usr/bin/security not found on PATH")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(home, "Library", "Application Support", "cloakline")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("keyvault: create %s: %w", dir, err)
	}
	return &darwinBackend{indexPath: filepath.Join(dir, "providers.index")}, nil
}

func (d *darwinBackend) Name() string { return "macos-keychain" }

func (d *darwinBackend) Set(provider, key string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	// -U updates in place if an item with the same service+account exists.
	cmd := exec.Command("security",
		"add-generic-password",
		"-U",
		"-s", darwinKeychainService,
		"-a", provider,
		"-w", key,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("security add-generic-password: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return d.addToIndex(provider)
}

func (d *darwinBackend) Get(provider string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	cmd := exec.Command("security",
		"find-generic-password",
		"-s", darwinKeychainService,
		"-a", provider,
		"-w",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if strings.Contains(stderr.String(), "could not be found") {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("security find-generic-password: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimRight(stdout.String(), "\n"), nil
}

func (d *darwinBackend) Delete(provider string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	cmd := exec.Command("security",
		"delete-generic-password",
		"-s", darwinKeychainService,
		"-a", provider,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if strings.Contains(stderr.String(), "could not be found") {
			_ = d.removeFromIndex(provider) // keep index consistent
			return ErrNotFound
		}
		return fmt.Errorf("security delete-generic-password: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return d.removeFromIndex(provider)
}

func (d *darwinBackend) List() ([]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.readIndex()
}

// --- provider-name index (no secrets) ---

func (d *darwinBackend) readIndex() ([]string, error) {
	data, err := os.ReadFile(d.indexPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	for _, line := range strings.Split(string(data), "\n") {
		p := strings.TrimSpace(line)
		if p == "" {
			continue
		}
		seen[p] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

func (d *darwinBackend) writeIndex(providers []string) error {
	sort.Strings(providers)
	buf := strings.Join(providers, "\n")
	if buf != "" {
		buf += "\n"
	}
	return os.WriteFile(d.indexPath, []byte(buf), 0o600)
}

func (d *darwinBackend) addToIndex(provider string) error {
	list, err := d.readIndex()
	if err != nil {
		return err
	}
	for _, p := range list {
		if p == provider {
			return nil
		}
	}
	return d.writeIndex(append(list, provider))
}

func (d *darwinBackend) removeFromIndex(provider string) error {
	list, err := d.readIndex()
	if err != nil {
		return err
	}
	out := make([]string, 0, len(list))
	for _, p := range list {
		if p != provider {
			out = append(out, p)
		}
	}
	return d.writeIndex(out)
}
