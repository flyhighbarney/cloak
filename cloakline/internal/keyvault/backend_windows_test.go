//go:build windows

package keyvault

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// newWindowsBackendAt is a test seam: it points the Windows backend at
// a caller-supplied directory instead of %LOCALAPPDATA%\cloakline\keys.
// Kept in the test file so production callers only see newOSBackend().
func newWindowsBackendAt(t *testing.T, dir string) *windowsBackend {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	return &windowsBackend{dir: dir}
}

// TestWindowsBackendSurvivesRestart proves the property the user asked
// for: keys are still there after the app (and the machine) restarts.
// A restart, from the backend's perspective, is exactly a fresh
// windowsBackend instance pointed at the same on-disk directory. If
// the second instance can read what the first wrote, restarts are safe.
func TestWindowsBackendSurvivesRestart(t *testing.T) {
	dir := t.TempDir()

	// --- "run 1" — cloakline starts, user pastes a key, cloakline exits.
	b1 := newWindowsBackendAt(t, dir)
	if err := b1.Set("openai-default", "sk-real-secret-abc123"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := b1.Set("anthropic-default", "sk-ant-xyz789"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Files exist on disk between runs.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 files on disk, got %d", len(entries))
	}

	// --- "run 2" — cloakline restarts. New backend, same directory.
	b2 := newWindowsBackendAt(t, dir)
	got, err := b2.Get("openai-default")
	if err != nil {
		t.Fatalf("Get after restart: %v", err)
	}
	if got != "sk-real-secret-abc123" {
		t.Fatalf("value after restart = %q, want the original", got)
	}
	got2, err := b2.Get("anthropic-default")
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if got2 != "sk-ant-xyz789" {
		t.Fatalf("second value = %q, want the original", got2)
	}

	// List reports both providers.
	list, err := b2.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("List = %v, want 2 entries", list)
	}
}

// TestWindowsBackendDeleteRemovesFile confirms that Delete really
// clears state (not just an in-memory map somewhere).
func TestWindowsBackendDeleteRemovesFile(t *testing.T) {
	dir := t.TempDir()
	b := newWindowsBackendAt(t, dir)
	_ = b.Set("openai-default", "sk-x")
	if err := b.Delete("openai-default"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "openai-default.bin")); !os.IsNotExist(err) {
		t.Fatalf("file should be gone, got err=%v", err)
	}
	if err := b.Delete("openai-default"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second Delete should ErrNotFound, got %v", err)
	}
}
