package tlsinspect

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestConfirmStorePutTakeRoundTrip(t *testing.T) {
	s, err := newConfirmStore()
	if err != nil {
		t.Fatalf("newConfirmStore: %v", err)
	}
	defer s.Close()

	body := []byte(`{"model":"claude","messages":[{"role":"user","content":"my password is hunter2"}]}`)
	if err := s.Put("sess1", body, true, "claude"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, ok := s.TakeAndDecrypt("sess1")
	if !ok {
		t.Fatal("TakeAndDecrypt returned !ok")
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("plaintext mismatch")
	}
	if _, _, ok := s.Peek("sess1"); ok {
		t.Fatal("entry should be gone after TakeAndDecrypt")
	}
}

// TestPendingCiphertextHoldsNoPlaintext is the paranoia test: even
// when the map holds a flagged body, grepping the raw ciphertext for
// the plaintext must never match.
func TestPendingCiphertextHoldsNoPlaintext(t *testing.T) {
	s, err := newConfirmStore()
	if err != nil {
		t.Fatalf("newConfirmStore: %v", err)
	}
	defer s.Close()

	needle := "hunter2-distinctive-marker"
	body := []byte(`{"messages":[{"role":"user","content":"here is my password: ` + needle + `"}]}`)
	if err := s.Put("sess1", body, false, ""); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Grep every ciphertext buffer in the map.
	s.mu.Lock()
	for k, e := range s.pending {
		if bytes.Contains(e.ciphertext, []byte(needle)) {
			s.mu.Unlock()
			t.Fatalf("ciphertext for session %s contains plaintext needle — encryption is broken", k)
		}
	}
	s.mu.Unlock()
}

// TestSingleUserFallbackConsumesPendingAcrossSessionKeys reproduces
// the OAuth-rotation incident: turn 1's session key differs from
// turn 2's (because the CLI refreshed its bearer), but there's only
// one human at the keyboard, so the sole pending entry should still
// be findable by the answer request.
func TestSingleUserFallbackConsumesPendingAcrossSessionKeys(t *testing.T) {
	s, err := newConfirmStore()
	if err != nil {
		t.Fatalf("newConfirmStore: %v", err)
	}
	defer s.Close()

	original := []byte(`{"messages":[{"role":"user","content":"password: hunter22"}]}`)
	if err := s.Put("turn1-session-key", original, false, "claude"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Turn 2 arrives with a DIFFERENT session key (OAuth rotated).
	_, _, ok := s.Peek("turn2-DIFFERENT-key")
	if !ok {
		t.Fatal("Peek should fall through to the sole pending entry")
	}
	got, ok := s.TakeAndDecrypt("turn2-DIFFERENT-key")
	if !ok {
		t.Fatal("TakeAndDecrypt should also fall through")
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("got the wrong body back")
	}
	// The single-user fallback should NOT trigger when there's 2+
	// pending entries — we can't disambiguate.
	_ = s.Put("session-A", []byte("bodyA"), false, "")
	_ = s.Put("session-B", []byte("bodyB"), false, "")
	if _, _, ok := s.Peek("session-C"); ok {
		t.Fatal("with 2 pending entries, Peek(nonMatching) must NOT fall through")
	}
}

// TestPendingLazyExpiryOnRead: an entry past its TTL must be
// invisible on the very next Peek / TakeAndDecrypt — no waiting for
// the background sweeper.
func TestPendingLazyExpiryOnRead(t *testing.T) {
	s, err := newConfirmStore()
	if err != nil {
		t.Fatalf("newConfirmStore: %v", err)
	}
	defer s.Close()

	_ = s.Put("sess1", []byte("body"), false, "")

	// Backdate the entry so it's already past TTL.
	s.mu.Lock()
	s.pending["sess1"].created = time.Now().Add(-2 * pendingTTL)
	s.mu.Unlock()

	if _, _, ok := s.Peek("sess1"); ok {
		t.Fatal("Peek must not return an expired entry")
	}
	if _, ok := s.TakeAndDecrypt("sess1"); ok {
		t.Fatal("TakeAndDecrypt must not return an expired entry")
	}
	if s.PendingCount() != 0 {
		t.Fatalf("expired entry should have been evicted, PendingCount=%d", s.PendingCount())
	}
}

func TestConfirmStoreDrop(t *testing.T) {
	s, _ := newConfirmStore()
	defer s.Close()
	_ = s.Put("sess1", []byte("body"), false, "")
	s.Drop("sess1")
	if _, _, ok := s.Peek("sess1"); ok {
		t.Fatal("entry should be gone after Drop")
	}
}

func TestConfirmStoreEvictsOldestOverCap(t *testing.T) {
	s, _ := newConfirmStore()
	defer s.Close()

	for i := 0; i < pendingCap+3; i++ {
		if err := s.Put(sessKey(i), []byte("body"), false, ""); err != nil {
			t.Fatalf("Put[%d]: %v", i, err)
		}
		// Advance the clock a bit so 'oldest' is well-defined.
		time.Sleep(1 * time.Millisecond)
	}
	if s.PendingCount() != pendingCap {
		t.Fatalf("PendingCount = %d, want %d", s.PendingCount(), pendingCap)
	}
	// The first three should be gone.
	for i := 0; i < 3; i++ {
		if _, _, ok := s.Peek(sessKey(i)); ok {
			t.Errorf("sess%d should have been evicted", i)
		}
	}
}

func TestConfirmStoreOptOut(t *testing.T) {
	s, _ := newConfirmStore()
	defer s.Close()

	if s.IsOptedOut("sess1") {
		t.Fatal("fresh session should not be opted out")
	}
	s.OptOut("sess1")
	if !s.IsOptedOut("sess1") {
		t.Fatal("after OptOut, IsOptedOut should be true")
	}
}

func TestParseUserAnswer(t *testing.T) {
	tmpl := func(text string) []byte {
		return []byte(`{"messages":[{"role":"user","content":"` + text + `"}]}`)
	}
	cases := []struct {
		in   string
		want userAnswer
	}{
		{"y", answerYes},
		{"yes", answerYes},
		{"Y", answerYes},
		{" YES ", answerYes},
		{"n", answerNo},
		{"no", answerNo},
		{"session", answerSession},
		{"disable", answerSession},
		{"help me", answerNone},
		{"", answerNone},
	}
	for _, c := range cases {
		if got := parseUserAnswer(tmpl(c.in)); got != c.want {
			t.Errorf("parseUserAnswer(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestSessionKeyStableAndDifferent(t *testing.T) {
	a := SessionKey("Bearer abc", "")
	b := SessionKey("Bearer abc", "")
	c := SessionKey("Bearer xyz", "")
	if a != b {
		t.Errorf("same auth should produce same key: %q != %q", a, b)
	}
	if a == c {
		t.Errorf("different auth should produce different keys")
	}
	if strings.Contains(a, "Bearer") || strings.Contains(a, "abc") {
		t.Errorf("session key should not contain the auth string in cleartext: %q", a)
	}
}

// TestSessionKeyEmptyHeadersReturnsEmpty is the regression for finding
// #1: unauthenticated clients must NOT collide on a single key.
func TestSessionKeyEmptyHeadersReturnsEmpty(t *testing.T) {
	if k := SessionKey("", ""); k != "" {
		t.Fatalf("SessionKey with both headers empty should return \"\", got %q", k)
	}
	// Non-empty in either slot must produce a real key.
	if k := SessionKey("Bearer x", ""); k == "" {
		t.Fatal("SessionKey with non-empty auth should produce a key")
	}
	if k := SessionKey("", "some-api-key"); k == "" {
		t.Fatal("SessionKey with non-empty api-key should produce a key")
	}
}

// TestSessionKeyStableAcrossTokenSuffixRotation covers finding #1's
// other half: an OAuth token whose stable prefix stays the same but
// whose signature suffix rotates should still produce the same key.
// We truncate at prefixLen=128 so anything after that is ignored.
func TestSessionKeyStableAcrossTokenSuffixRotation(t *testing.T) {
	stablePrefix := strings.Repeat("A", 128)
	rotatedA := "Bearer " + stablePrefix + ".signatureA"
	rotatedB := "Bearer " + stablePrefix + ".signatureB.different.length"
	// Both should hash to the same key because we only look at the
	// first 128 chars of the auth header.
	if SessionKey(rotatedA, "") != SessionKey(rotatedB, "") {
		t.Fatal("session key should be stable across rotating suffix beyond 128-char prefix")
	}
	// Sanity: differing WITHIN the 128-char window still produces
	// different keys.
	if SessionKey("Bearer aaa", "") == SessionKey("Bearer bbb", "") {
		t.Fatal("short auth headers with different prefixes should differ")
	}
}

func sessKey(i int) string {
	return "session-" + string(rune('0'+i))
}
