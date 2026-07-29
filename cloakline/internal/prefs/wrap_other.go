//go:build !windows

package prefs

// On non-Windows platforms the key is stored raw with 0o600 perms.
// This is weaker than DPAPI: any process running as the same UID can
// read it. A future native-keyring binding (see docs/tripwires.md
// T-KEYVAULT-KEYRING) will replace this with a real OS-backed wrap.

func wrapKeyForDisk(key []byte) ([]byte, error) {
	out := make([]byte, len(key))
	copy(out, key)
	return out, nil
}

func unwrapKeyFromDisk(wrapped []byte) ([]byte, error) {
	out := make([]byte, len(wrapped))
	copy(out, wrapped)
	return out, nil
}
