//go:build !windows && !darwin

package keyvault

// newOSBackend on unsupported platforms returns (nil, nil) — the
// in-memory backend remains active. Native backends exist for Windows
// (DPAPI, backend_windows.go) and macOS (Keychain, backend_darwin.go).
// Linux Secret Service is the next candidate.
func newOSBackend() (Backend, error) {
	return nil, nil
}
