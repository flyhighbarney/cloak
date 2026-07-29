package engine

import (
	"crypto/rand"
	"encoding/hex"
)

// newRandID returns an n-hex-char random identifier. n must be even.
// Used when a request or session ID is missing on entry to Handle so the
// vault has a stable key to open under.
func newRandID(n int) string {
	b := make([]byte, n/2)
	if _, err := rand.Read(b); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(b)
}
