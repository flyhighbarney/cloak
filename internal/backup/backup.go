// Package backup provides automatic, dependency-free snapshots of
// cloakline's mutable state (config, encrypted prefs/vault, local CA, and a
// copy of the OS hosts file) so a bad edit, a corrupted vault, or a botched
// upgrade is always one restore away.
//
// It is designed to run UNATTENDED at daemon startup: take a snapshot, keep
// the newest N, delete the rest. The user never has to think about it. All
// failures are non-fatal to the caller — a backup that can't be written logs
// and is skipped; it must never stop cloakline from starting.
package backup

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Source is one thing to include in a snapshot. Path may be a file or a
// directory (directories are walked recursively). Missing paths are skipped
// silently — cloakline snapshots a superset of what any given install has.
type Source struct {
	// Path is the absolute path on disk.
	Path string
	// Label is the top-level folder name inside the archive. Keeps the
	// archive readable and avoids collisions between sources.
	Label string
}

// Snapshot writes a zip of every existing Source into destDir and returns the
// archive path. The filename is backup-<UTC-timestamp>.zip so lexical sort ==
// chronological sort (used by Rotate).
func Snapshot(destDir string, sources []Source) (string, error) {
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return "", fmt.Errorf("backup: mkdir %s: %w", destDir, err)
	}
	name := "backup-" + time.Now().UTC().Format("20060102T150405Z") + ".zip"
	out := filepath.Join(destDir, name)

	f, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("backup: create %s: %w", out, err)
	}
	// Clean up a half-written archive on any error.
	success := false
	defer func() {
		f.Close()
		if !success {
			_ = os.Remove(out)
		}
	}()

	zw := zip.NewWriter(f)
	for _, s := range sources {
		info, statErr := os.Stat(s.Path)
		if statErr != nil {
			continue // missing source — skip, not an error
		}
		if info.IsDir() {
			if err := addDir(zw, s.Path, s.Label); err != nil {
				return "", err
			}
			continue
		}
		if err := addFile(zw, s.Path, filepath.Join(s.Label, info.Name())); err != nil {
			return "", err
		}
	}
	if err := zw.Close(); err != nil {
		return "", fmt.Errorf("backup: finalize: %w", err)
	}
	success = true
	return out, nil
}

func addDir(zw *zip.Writer, root, label string) error {
	return filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // unreadable entry — skip
		}
		if info.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return nil
		}
		return addFile(zw, p, filepath.Join(label, rel))
	})
}

func addFile(zw *zip.Writer, srcPath, archivePath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return nil // vanished/locked between stat and open — skip
	}
	defer src.Close()
	// zip uses forward slashes.
	w, err := zw.Create(strings.ReplaceAll(archivePath, string(os.PathSeparator), "/"))
	if err != nil {
		return fmt.Errorf("backup: zip entry %s: %w", archivePath, err)
	}
	if _, err := io.Copy(w, src); err != nil {
		return fmt.Errorf("backup: copy %s: %w", srcPath, err)
	}
	return nil
}

// Rotate keeps the newest `keep` backup-*.zip archives in dir and deletes the
// rest. keep <= 0 is treated as 1 (never leave zero backups after a snapshot).
func Rotate(dir string, keep int) error {
	if keep <= 0 {
		keep = 1
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("backup: read %s: %w", dir, err)
	}
	var archives []string
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, "backup-") && strings.HasSuffix(n, ".zip") {
			archives = append(archives, n)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(archives))) // newest first
	for i, n := range archives {
		if i < keep {
			continue
		}
		_ = os.Remove(filepath.Join(dir, n))
	}
	return nil
}

// Restore extracts archive into destRoot, recreating the Label/… layout. It
// refuses zip-slip paths that escape destRoot. Existing files are overwritten.
func Restore(archive, destRoot string) error {
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return fmt.Errorf("backup: open %s: %w", archive, err)
	}
	defer zr.Close()

	root, err := filepath.Abs(destRoot)
	if err != nil {
		return err
	}
	for _, zf := range zr.File {
		target := filepath.Join(root, filepath.FromSlash(zf.Name))
		// zip-slip guard: target must stay under root.
		if !strings.HasPrefix(target, root+string(os.PathSeparator)) && target != root {
			return fmt.Errorf("backup: refusing unsafe path %q", zf.Name)
		}
		if zf.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		if err := extractOne(zf, target); err != nil {
			return err
		}
	}
	return nil
}

func extractOne(zf *zip.File, target string) error {
	rc, err := zf.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, rc); err != nil {
		return err
	}
	return nil
}

// Auto is the one-call convenience the daemon uses at startup: snapshot the
// given sources into destDir, then rotate to keep the newest `keep`. Errors
// are returned for logging but the daemon treats them as non-fatal.
func Auto(destDir string, sources []Source, keep int) (string, error) {
	path, err := Snapshot(destDir, sources)
	if err != nil {
		return "", err
	}
	if err := Rotate(destDir, keep); err != nil {
		return path, err // snapshot succeeded; rotation hiccup is minor
	}
	return path, nil
}
