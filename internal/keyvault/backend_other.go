//go:build !windows

package keyvault

// newOSBackend on non-Windows platforms returns (nil, nil) — the
// in-memory backend remains active. A native macOS Keychain / Linux
// Secret Service backend is a follow-up; when it lands it replaces
// this file's build tag.
func newOSBackend() (Backend, error) {
	return nil, nil
}
