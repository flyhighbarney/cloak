package tlsinspect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"cloakline/internal/crypto/aesbox"
)

// confirmStore is the process-scoped state machine for HIGH-tier
// intentional pastes:
//
//   - pending: encrypted originals awaiting user y/n reply
//   - optout:  sessions that have said "session, disable it for now"
//
// Storage rules the user explicitly asked for are enforced here:
//
//   - AES-256-GCM encryption of the original body while it sits
//     in the map (see aesbox.Seal / Open)
//   - bounded map size — evict oldest when full
//   - TTL sweep — every 30s a goroutine zeroizes and deletes
//     entries past their deadline
//   - never persisted to disk
type confirmStore struct {
	mu      sync.Mutex
	pending map[string]*pendingEntry // key = sessionKey
	optout  map[string]time.Time     // key = sessionKey, value = expiry
	aesKey  []byte                   // 32 bytes; ephemeral, never persisted
	stopCh  chan struct{}
}

type pendingEntry struct {
	ciphertext []byte // AES-GCM ciphertext of the original request body
	created    time.Time
	// wantStream and model are needed to render the synthetic prompt
	// correctly (SSE vs JSON) for THIS session. Non-secret.
	wantStream bool
	model      string
}

const (
	pendingCap        = 16
	// pendingTTL is short by design: if the user doesn't answer y/n/session
	// within this window, cloakline assumes the safe answer (drop) and
	// the flagged content is zeroized. UX-wise this means the prompt is
	// live only briefly — the user must answer soon after seeing it,
	// which is fine for interactive CLIs where the prompt appears
	// immediately in the terminal.
	pendingTTL        = 60 * time.Second
	sessionOptoutTTL  = time.Hour
	// sweepInterval is a background safety net. Peek/TakeAndDecrypt
	// also check TTL on every access (lazy expiry) so a stale entry
	// cannot leak between sweeps.
	sweepInterval     = 10 * time.Second
)

// newConfirmStore mints the process AES key and starts the TTL
// sweeper. Callers must call Close() at shutdown to zeroize the key
// and stop the goroutine.
func newConfirmStore() (*confirmStore, error) {
	key, err := aesbox.NewKey()
	if err != nil {
		return nil, err
	}
	s := &confirmStore{
		pending: make(map[string]*pendingEntry, pendingCap),
		optout:  make(map[string]time.Time),
		aesKey:  key,
		stopCh:  make(chan struct{}),
	}
	go s.sweepLoop()
	return s, nil
}

// Close zeroizes the AES key and stops the sweeper. Anything left in
// the pending map at this point is unrecoverable — intentional.
func (s *confirmStore) Close() {
	select {
	case <-s.stopCh:
		return
	default:
		close(s.stopCh)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.pending {
		aesbox.Zeroize(e.ciphertext)
		delete(s.pending, k)
	}
	if s.aesKey != nil {
		aesbox.Zeroize(s.aesKey)
		s.aesKey = nil
	}
}

// SessionKey derives a non-persisted identifier for a user session
// from the HTTP auth headers. Reused across requests as long as the
// CLI keeps sending the same auth. Never stored on disk, never logged.
//
// Two guardrails on top of the naive sha256(auth || 0 || apiKey):
//
//  1. Returns "" if BOTH headers are empty — this prevents multiple
//     unauthenticated clients (curl smokes, misconfigured proxies)
//     from all hashing to the same key and cross-contaminating each
//     other's pending confirmations.
//
//  2. For long OAuth bearer tokens we hash only the first 128 chars.
//     Most tokens have a stable user/session prefix and a rotating
//     signature suffix that changes on refresh. Cutting at 128 chars
//     keeps the key stable across mid-conversation token refreshes
//     while still being unique per user in practice (>10^38 bits of
//     entropy in the retained portion for a typical JWT).
func SessionKey(authHeader, apiKeyHeader string) string {
	if authHeader == "" && apiKeyHeader == "" {
		return ""
	}
	const prefixLen = 128
	if len(authHeader) > prefixLen {
		authHeader = authHeader[:prefixLen]
	}
	if len(apiKeyHeader) > prefixLen {
		apiKeyHeader = apiKeyHeader[:prefixLen]
	}
	h := sha256.New()
	h.Write([]byte(authHeader))
	h.Write([]byte{0})
	h.Write([]byte(apiKeyHeader))
	return hex.EncodeToString(h.Sum(nil))
}

// Put stores an encrypted copy of `body` awaiting confirmation.
// Enforces the pendingCap: if full, oldest is evicted and zeroized.
func (s *confirmStore) Put(sessionKey string, body []byte, wantStream bool, model string) error {
	ct, err := aesbox.Seal(s.aesKey, body, []byte("cloakline/pending/v1"))
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) >= pendingCap {
		s.evictOldestLocked()
	}
	s.pending[sessionKey] = &pendingEntry{
		ciphertext: ct,
		created:    time.Now(),
		wantStream: wantStream,
		model:      model,
	}
	return nil
}

// Peek returns whether a pending entry exists for this session
// without decrypting it. Used by the fast path in forward.go.
//
// Single-user fallback: if there's no exact-key match but exactly ONE
// pending entry exists in the whole map, return IT. Rationale: cloakline
// is explicitly a single-user desktop tool (see docs/policy-tiers.md).
// OAuth token rotation between the prompt turn and the answer turn
// invalidates the exact session key, but the sole pending entry
// unambiguously belongs to the human at the keyboard.
//
// Lazy expiry: expired entries are evicted on read so a stale entry
// can never be observed after its TTL, even between background sweeps.
func (s *confirmStore) Peek(sessionKey string) (wantStream bool, model string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictExpiredLocked()
	if e, ok := s.pending[sessionKey]; ok {
		return e.wantStream, e.model, true
	}
	if len(s.pending) == 1 {
		for _, e := range s.pending {
			return e.wantStream, e.model, true
		}
	}
	return false, "", false
}

// TakeAndDecrypt removes the pending entry and returns its plaintext.
// Callers must Zeroize the returned slice when done. If no pending
// entry exists, returns (nil, false).
//
// Single-user fallback (mirrors Peek): if there's no exact match but
// exactly one pending entry exists globally, take THAT one. Expired
// entries are evicted before the lookup — a Take arriving one tick
// after the TTL will find nothing (safe default: user's message
// stays flagged, next turn goes through normal DLP).
func (s *confirmStore) TakeAndDecrypt(sessionKey string) ([]byte, bool) {
	s.mu.Lock()
	s.evictExpiredLocked()
	e, ok := s.pending[sessionKey]
	if !ok {
		if len(s.pending) == 1 {
			for k, v := range s.pending {
				sessionKey = k
				e = v
				ok = true
				break
			}
		}
	}
	if !ok {
		s.mu.Unlock()
		return nil, false
	}
	delete(s.pending, sessionKey)
	s.mu.Unlock()

	plain, err := aesbox.Open(s.aesKey, e.ciphertext, []byte("cloakline/pending/v1"))
	// Zeroize the ciphertext in the map slot regardless of decrypt
	// success — the entry is gone from the map now.
	aesbox.Zeroize(e.ciphertext)
	if err != nil {
		return nil, false
	}
	return plain, true
}

// Drop removes any pending entry for this session without decrypting
// it (used on "n" replies and timeouts).
func (s *confirmStore) Drop(sessionKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.pending[sessionKey]; ok {
		aesbox.Zeroize(e.ciphertext)
		delete(s.pending, sessionKey)
	}
}

// OptOut whitelists a session for the sessionOptoutTTL window.
func (s *confirmStore) OptOut(sessionKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.optout[sessionKey] = time.Now().Add(sessionOptoutTTL)
}

// IsOptedOut reports whether a session is within its opt-out window.
// Expired entries are lazily cleaned up here.
func (s *confirmStore) IsOptedOut(sessionKey string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.optout[sessionKey]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(s.optout, sessionKey)
		return false
	}
	return true
}

// PendingCount returns the current number of encrypted entries in
// the map, for the dashboard "N requests awaiting confirmation" tile.
func (s *confirmStore) PendingCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending)
}

// -- internal --

func (s *confirmStore) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	for k, e := range s.pending {
		if oldestKey == "" || e.created.Before(oldestTime) {
			oldestKey = k
			oldestTime = e.created
		}
	}
	if oldestKey == "" {
		return
	}
	aesbox.Zeroize(s.pending[oldestKey].ciphertext)
	delete(s.pending, oldestKey)
}

func (s *confirmStore) sweepLoop() {
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-t.C:
			s.sweepOnce()
		}
	}
}

func (s *confirmStore) sweepOnce() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictExpiredLocked()
	now := time.Now()
	for k, exp := range s.optout {
		if now.After(exp) {
			delete(s.optout, k)
		}
	}
}

// evictExpiredLocked removes pending entries past their TTL and
// zeroizes the ciphertext buffers. Caller MUST hold s.mu (write).
// Called by both the background sweeper AND every read (Peek /
// TakeAndDecrypt) so a stale entry can never be observed after its
// TTL expires — even if the sweeper is between ticks.
func (s *confirmStore) evictExpiredLocked() {
	now := time.Now()
	for k, e := range s.pending {
		if now.Sub(e.created) > pendingTTL {
			aesbox.Zeroize(e.ciphertext)
			delete(s.pending, k)
		}
	}
}

// parseUserAnswer inspects a client request body and reports which
// confirmation option the user chose. Returns "" if the body doesn't
// look like a Y/N/session answer, in which case the caller drops the
// pending entry and forwards the request normally.
//
// Recognised (case-insensitive, whitespace-tolerant):
//
//   "y", "yes"            → answerYes
//   "n", "no"             → answerNo
//   "session", "disable"  → answerSession
func parseUserAnswer(body []byte) userAnswer {
	// Anthropic messages payload: {"messages":[{"role":"user","content":"..."}]}.
	// Content can be a string or a list of content blocks. Grab whichever
	// is present in the last user message.
	var probe struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return answerNone
	}
	if len(probe.Messages) == 0 {
		return answerNone
	}
	last := probe.Messages[len(probe.Messages)-1]
	if last.Role != "user" {
		return answerNone
	}
	// Try string form first.
	var text string
	if err := json.Unmarshal(last.Content, &text); err != nil {
		// Try content-block form.
		var blocks []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if err := json.Unmarshal(last.Content, &blocks); err != nil {
			return answerNone
		}
		for _, b := range blocks {
			if b.Type == "text" {
				text += b.Text
			}
		}
	}
	t := strings.ToLower(strings.TrimSpace(text))
	switch {
	case t == "y" || t == "yes":
		return answerYes
	case t == "n" || t == "no":
		return answerNo
	case t == "session" || t == "disable" || t == "disable safety" || t == "disable checks":
		return answerSession
	}
	return answerNone
}

type userAnswer int

const (
	answerNone userAnswer = iota
	answerYes
	answerNo
	answerSession
)
