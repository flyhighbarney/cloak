package log

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// DefaultLogDir returns the platform log directory:
//
//	%LOCALAPPDATA%\cloakline\logs  (Windows)
//	$XDG_CONFIG_HOME/cloakline/logs  (Linux/macOS)
func DefaultLogDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "cloakline", "logs"), nil
}

// DefaultLogFile is the path OpenFile writes to by default.
func DefaultLogFile() (string, error) {
	dir, err := DefaultLogDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "cloakline.log"), nil
}

const (
	maxLogFileBytes = 5 << 20 // 5 MiB per file
	maxLogBackups   = 2       // +1 active = 15 MiB total on disk
)

// rotatingFile is an io.WriteCloser that rotates itself once it exceeds
// maxLogFileBytes, keeping up to maxLogBackups previous files
// (cloakline.log.1 .. cloakline.log.N). This exists so a long-running
// daemon never fills the disk with an unbounded log, while still leaving
// enough history on disk for a user to hand an error to support/Claude.
type rotatingFile struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64
}

// OpenFile opens (creating parent dirs as needed) the rotating log file at
// path for appending. The returned io.WriteCloser is safe for concurrent
// use and should be Close()'d at process exit.
func OpenFile(path string) (io.WriteCloser, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("log: mkdir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("log: open: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("log: stat: %w", err)
	}
	return &rotatingFile{path: path, f: f, size: info.Size()}, nil
}

func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.size+int64(len(p)) > maxLogFileBytes {
		if err := r.rotateLocked(); err != nil {
			// Fall through and keep writing to the current file rather
			// than dropping the log line — a failed rotation shouldn't
			// silence the daemon.
			_ = err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *rotatingFile) rotateLocked() error {
	if err := r.f.Close(); err != nil {
		return err
	}
	for i := maxLogBackups - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", r.path, i)
		dst := fmt.Sprintf("%s.%d", r.path, i+1)
		_ = os.Rename(src, dst)
	}
	_ = os.Rename(r.path, r.path+".1")
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	r.f = f
	r.size = 0
	return nil
}

func (r *rotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}
