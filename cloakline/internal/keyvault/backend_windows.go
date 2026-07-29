//go:build windows

package keyvault

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

// windowsBackend persists keys as DPAPI-encrypted files under
// %LOCALAPPDATA%\cloakline\keys\<provider>.bin. DPAPI (Data Protection API)
// ties the ciphertext to the current Windows user account: only a
// process running as the same user can decrypt.
//
// No external Go dependency: crypt32.dll is loaded via syscall.
type windowsBackend struct {
	mu  sync.Mutex
	dir string
}

func newOSBackend() (Backend, error) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local")
	}
	if base == "" {
		return nil, fmt.Errorf("keyvault: cannot determine LOCALAPPDATA")
	}
	dir := filepath.Join(base, "cloakline", "keys")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("keyvault: create %s: %w", dir, err)
	}
	return &windowsBackend{dir: dir}, nil
}

func (w *windowsBackend) Name() string { return "windows-dpapi" }

func (w *windowsBackend) path(provider string) string {
	return filepath.Join(w.dir, provider+".bin")
}

func (w *windowsBackend) Set(provider, key string) error {
	ct, err := dpapiProtect([]byte(key))
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return os.WriteFile(w.path(provider), ct, 0o600)
}

func (w *windowsBackend) Get(provider string) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	ct, err := os.ReadFile(w.path(provider))
	if os.IsNotExist(err) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	pt, err := dpapiUnprotect(ct)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

func (w *windowsBackend) Delete(provider string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	err := os.Remove(w.path(provider))
	if os.IsNotExist(err) {
		return ErrNotFound
	}
	return err
}

func (w *windowsBackend) List() ([]string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if !strings.HasSuffix(n, ".bin") {
			continue
		}
		out = append(out, strings.TrimSuffix(n, ".bin"))
	}
	sort.Strings(out)
	return out, nil
}

// --- DPAPI bindings ---
//
// Direct syscalls into crypt32.dll. Kept small on purpose: only the two
// entry points we need, and the DATA_BLOB struct required to pass bytes
// across the ABI boundary.

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newBlob(b []byte) *dataBlob {
	if len(b) == 0 {
		return &dataBlob{}
	}
	return &dataBlob{cbData: uint32(len(b)), pbData: &b[0]}
}

func (b *dataBlob) toBytes() []byte {
	if b.cbData == 0 || b.pbData == nil {
		return nil
	}
	// Copy out of DPAPI-owned memory before we LocalFree it.
	src := unsafe.Slice(b.pbData, int(b.cbData))
	dst := make([]byte, b.cbData)
	copy(dst, src)
	return dst
}

var (
	crypt32                = syscall.NewLazyDLL("crypt32.dll")
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procCryptProtectData   = crypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
	procLocalFree          = kernel32.NewProc("LocalFree")
)

const cryptprotectUIForbidden = 0x1

func dpapiProtect(data []byte) ([]byte, error) {
	in := newBlob(data)
	var out dataBlob
	ret, _, err := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(in)),
		0, 0, 0, 0,
		cryptprotectUIForbidden,
		uintptr(unsafe.Pointer(&out)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("CryptProtectData: %w", err)
	}
	result := out.toBytes()
	procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	return result, nil
}

func dpapiUnprotect(data []byte) ([]byte, error) {
	in := newBlob(data)
	var out dataBlob
	ret, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(in)),
		0, 0, 0, 0,
		cryptprotectUIForbidden,
		uintptr(unsafe.Pointer(&out)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("CryptUnprotectData: %w", err)
	}
	result := out.toBytes()
	procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	return result, nil
}
