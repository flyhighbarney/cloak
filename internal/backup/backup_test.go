package backup

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSnapshotRestoreRoundTrip: state written, backed up, wiped, restored,
// and the bytes match. This is the core promise of the backup system.
func TestSnapshotRestoreRoundTrip(t *testing.T) {
	tmp := t.TempDir()

	// Fake state dir with a nested file (mimics ca/ + prefs.bin).
	stateDir := filepath.Join(tmp, "state")
	if err := os.MkdirAll(filepath.Join(stateDir, "ca"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(stateDir, "prefs.bin"), "secret-prefs")
	writeFile(t, filepath.Join(stateDir, "ca", "root.pem"), "PEM DATA")

	// A standalone config file.
	cfg := filepath.Join(tmp, "pipeline.yaml")
	writeFile(t, cfg, "inspect: {enabled: true}")

	dest := filepath.Join(tmp, "backups")
	sources := []Source{
		{Path: stateDir, Label: "state"},
		{Path: cfg, Label: "config"},
		{Path: filepath.Join(tmp, "does-not-exist"), Label: "missing"}, // must be skipped
	}

	archive, err := Snapshot(dest, sources)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if _, err := os.Stat(archive); err != nil {
		t.Fatalf("archive missing: %v", err)
	}

	// Restore into a clean root.
	restoreRoot := filepath.Join(tmp, "restored")
	if err := Restore(archive, restoreRoot); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	assertFile(t, filepath.Join(restoreRoot, "state", "prefs.bin"), "secret-prefs")
	assertFile(t, filepath.Join(restoreRoot, "state", "ca", "root.pem"), "PEM DATA")
	assertFile(t, filepath.Join(restoreRoot, "config", "pipeline.yaml"), "inspect: {enabled: true}")
}

// TestRotateKeepsNewest: after many snapshots, only the newest `keep` survive.
func TestRotateKeepsNewest(t *testing.T) {
	tmp := t.TempDir()
	dest := filepath.Join(tmp, "backups")
	if err := os.MkdirAll(dest, 0o700); err != nil {
		t.Fatal(err)
	}
	// Hand-create archives with sortable names.
	names := []string{
		"backup-20260101T000000Z.zip",
		"backup-20260102T000000Z.zip",
		"backup-20260103T000000Z.zip",
		"backup-20260104T000000Z.zip",
		"not-a-backup.txt", // must be ignored
	}
	for _, n := range names {
		writeFile(t, filepath.Join(dest, n), "x")
	}
	if err := Rotate(dest, 2); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	// Newest two + the non-backup file remain.
	assertExists(t, filepath.Join(dest, "backup-20260104T000000Z.zip"), true)
	assertExists(t, filepath.Join(dest, "backup-20260103T000000Z.zip"), true)
	assertExists(t, filepath.Join(dest, "backup-20260102T000000Z.zip"), false)
	assertExists(t, filepath.Join(dest, "backup-20260101T000000Z.zip"), false)
	assertExists(t, filepath.Join(dest, "not-a-backup.txt"), true)
}

// TestRestoreRejectsZipSlip: a malicious archive can't escape the dest root.
func TestRestoreRejectsZipSlip(t *testing.T) {
	tmp := t.TempDir()
	// Build a source whose label tries to traverse up. Snapshot sanitizes
	// separators, so craft the escape at restore time by using a source file
	// and a Label containing "..". Snapshot preserves the label verbatim.
	victim := filepath.Join(tmp, "src.txt")
	writeFile(t, victim, "data")

	dest := filepath.Join(tmp, "backups")
	archive, err := Snapshot(dest, []Source{{Path: victim, Label: "../../escape"}})
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	err = Restore(archive, filepath.Join(tmp, "restore"))
	if err == nil {
		t.Fatal("expected zip-slip to be refused, got nil")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertFile(t *testing.T, path, want string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(b) != want {
		t.Fatalf("%s: want %q, got %q", path, want, string(b))
	}
}

func assertExists(t *testing.T, path string, want bool) {
	t.Helper()
	_, err := os.Stat(path)
	if want && err != nil {
		t.Fatalf("expected %s to exist: %v", path, err)
	}
	if !want && err == nil {
		t.Fatalf("expected %s to be gone", path)
	}
}
