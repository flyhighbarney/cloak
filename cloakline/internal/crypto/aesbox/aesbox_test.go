package aesbox

import (
	"bytes"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	key, err := NewKey()
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	pt := []byte("my password is hunter2")
	box, err := Seal(key, pt, []byte("aad"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(box, pt) {
		t.Fatalf("ciphertext contains plaintext bytes — encryption is broken")
	}
	got, err := Open(key, box, []byte("aad"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("round-trip mismatch: got %q, want %q", got, pt)
	}
}

func TestOpenWithWrongAADFails(t *testing.T) {
	key, _ := NewKey()
	box, _ := Seal(key, []byte("data"), []byte("aad-1"))
	if _, err := Open(key, box, []byte("aad-2")); err == nil {
		t.Fatal("Open with wrong AAD should have failed")
	}
}

func TestOpenWithWrongKeyFails(t *testing.T) {
	k1, _ := NewKey()
	k2, _ := NewKey()
	box, _ := Seal(k1, []byte("data"), nil)
	if _, err := Open(k2, box, nil); err == nil {
		t.Fatal("Open with wrong key should have failed")
	}
}

func TestOpenRejectsTamperedCiphertext(t *testing.T) {
	key, _ := NewKey()
	box, _ := Seal(key, []byte("data"), nil)
	// Flip a bit in the middle.
	box[len(box)/2] ^= 1
	if _, err := Open(key, box, nil); err == nil {
		t.Fatal("Open of tampered ciphertext should have failed")
	}
}

func TestSealWithBadKeyRejects(t *testing.T) {
	if _, err := Seal(make([]byte, 16), []byte("x"), nil); err == nil {
		t.Fatal("Seal with 16-byte key should have failed")
	}
}

func TestZeroize(t *testing.T) {
	b := []byte("secret")
	Zeroize(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d is %d, want 0", i, v)
		}
	}
}

// TestGrepForPlaintextInCiphertext is a paranoia test: if someone
// ever silently replaces Seal with a no-op, this catches it before
// prod does.
func TestGrepForPlaintextInCiphertext(t *testing.T) {
	key, _ := NewKey()
	needles := [][]byte{
		[]byte("hunter2"),
		[]byte("AKIA0123456789ABCDEF"),
		[]byte("4111111111111111"),
		[]byte("sk-ant-abcd1234"),
	}
	for _, n := range needles {
		box, err := Seal(key, n, nil)
		if err != nil {
			t.Fatalf("Seal(%q): %v", n, err)
		}
		if bytes.Contains(box, n) {
			t.Fatalf("ciphertext contains needle %q — Seal is not encrypting", n)
		}
	}
}
