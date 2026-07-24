//go:build windows

package prefs

// On Windows, reuse the same DPAPI syscalls the keyvault backend uses.
// We deliberately don't export those from keyvault (it's a leaky
// abstraction), so this file has its own tiny wrapper.

import (
	"fmt"
	"syscall"
	"unsafe"
)

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

func wrapKeyForDisk(key []byte) ([]byte, error) {
	in := newBlob(key)
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

func unwrapKeyFromDisk(wrapped []byte) ([]byte, error) {
	in := newBlob(wrapped)
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
