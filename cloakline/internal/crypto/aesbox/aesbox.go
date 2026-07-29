// Package aesbox is a small AES-256-GCM helper.
//
// Two roles across the codebase:
//
//   1. In-memory encryption of high-risk material that we must briefly
//      hold (the confirmation-pending map). An ephemeral process key
//      is generated at startup and never persisted — a memory-dump
//      attacker would need both the map and the running process image
//      to recover plaintext.
//
//   2. At-rest encryption of prefs and any other non-secret-but-
//      sensitive artefact. On Windows the AES key is DPAPI-wrapped
//      via internal/keyvault; on other platforms it lives beside the
//      encrypted file with 0o600 perms (documented as a weaker mode).
//
// Nonces are 12 random bytes prepended to the ciphertext. The layout
// on disk / in the map is: nonce || ciphertext || GCM-tag.
package aesbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// KeySize is the required key length in bytes (32 for AES-256).
const KeySize = 32

// NonceSize is the GCM standard nonce size in bytes.
const NonceSize = 12

// ErrInvalidKey reports a key of the wrong length.
var ErrInvalidKey = errors.New("aesbox: key must be exactly 32 bytes")

// ErrShortCiphertext reports a ciphertext too small to contain a nonce.
var ErrShortCiphertext = errors.New("aesbox: ciphertext too short")

// NewKey returns a fresh 32-byte key sourced from crypto/rand.
// The caller is responsible for holding it securely and calling
// Zeroize when they're done with it.
func NewKey() ([]byte, error) {
	k := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil, fmt.Errorf("aesbox: read random key: %w", err)
	}
	return k, nil
}

// Seal encrypts plaintext under key and returns nonce||ciphertext||tag.
// Adds `aad` as authenticated-but-not-encrypted data (nil is fine).
func Seal(key, plaintext, aad []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aesbox: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aesbox: new gcm: %w", err)
	}
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("aesbox: read nonce: %w", err)
	}
	// Layout: nonce || sealed. gcm.Seal appends the tag to sealed.
	out := make([]byte, 0, NonceSize+len(plaintext)+gcm.Overhead())
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plaintext, aad), nil
}

// Open decrypts a nonce||ciphertext||tag blob produced by Seal.
// The returned slice is a fresh allocation; callers should Zeroize
// it when they're done with the plaintext.
func Open(key, box, aad []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}
	if len(box) < NonceSize+16 {
		return nil, ErrShortCiphertext
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aesbox: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aesbox: new gcm: %w", err)
	}
	nonce, ct := box[:NonceSize], box[NonceSize:]
	pt, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("aesbox: open: %w", err)
	}
	return pt, nil
}

// Zeroize overwrites b with zeros. Cheap defense-in-depth against
// accidental disclosure via later heap reuse or debuggers. Not a
// substitute for the OS's memory hygiene — a determined attacker
// with process access has already lost.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
