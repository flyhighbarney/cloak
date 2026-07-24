// Package audit is the in-memory ring buffer of recent request verdicts,
// backing the /admin dashboard.
//
// Deliberately NOT persistent — a restart clears the buffer. This aligns
// with Phase 1's "no database" constraint. A durable audit sink lands with
// tripwire T-AUDIT-CHAIN.
//
// Redaction rules for entries:
//   - Never store plaintext of DLP findings.
//   - Never store the raw prompt or the raw response.
//   - Store only: finding kinds, matched rule IDs, injection score.
//   - Store the request ID for correlation with structured logs.
package audit

import (
	"sync"
	"time"

	"cloakline/internal/api"
)

// Verdict summarizes what happened to a request.
type Verdict string

const (
	VerdictAllowed       Verdict = "allowed"
	VerdictRedacted      Verdict = "redacted"
	VerdictWarned        Verdict = "warned"
	VerdictBlockedDLP    Verdict = "blocked_dlp"
	VerdictBlockedPolicy Verdict = "blocked_policy"
	VerdictAuthFailed    Verdict = "auth_failed"
	VerdictUpstreamError Verdict = "upstream_error"
	VerdictError         Verdict = "error"
)

// Entry is one row in the admin dashboard. Content is fully redacted:
// only kinds, rule IDs, and identifiers are ever stored.
type Entry struct {
	Timestamp    time.Time
	RequestID    string
	TenantID     string
	KeyID        string
	Endpoint     string // "/v1/chat/completions" | "/v1/messages"
	Mode         string // "unary" | "streaming"
	Upstream     string // upstream ID that was chosen (empty if none)
	Model        string
	Verdict      Verdict
	DLPFindings  []string // finding kinds only, e.g. ["ssn","email"]
	InjectionScore int
	InjectionRules []string // matched rule IDs
	DurationMS   int64
	Error        string // sanitized error message (never plaintext content)
}

// Recorder is a bounded ring buffer of entries. Safe for concurrent use.
//
// Lifetime counters (fields prefixed `life`) accumulate across the whole
// process life and are the source of the Brave-style dashboard tiles.
// They reset on restart — the ring buffer is not durable by design.
type Recorder struct {
	mu       sync.Mutex
	entries  []Entry // circular
	head     int     // index of the next write
	capacity int
	total    uint64 // lifetime counter for stats

	lifeSecretsCaught     uint64
	lifePIIRedacted       uint64
	lifeInjectionsBlocked uint64
}

// New returns a Recorder that holds the most-recent `capacity` entries.
// Recommended: 1000 for a small-VPS deployment.
func New(capacity int) *Recorder {
	if capacity <= 0 {
		capacity = 1000
	}
	return &Recorder{
		entries:  make([]Entry, capacity),
		capacity: capacity,
	}
}

// Record appends an entry. The oldest entry is overwritten if full.
// The lifetime counters advance atomically with the ring write.
func (r *Recorder) Record(e Entry) {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	hadSecret, hadPII := Classify(e.DLPFindings)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[r.head] = e
	r.head = (r.head + 1) % r.capacity
	r.total++
	if hadSecret {
		r.lifeSecretsCaught++
	}
	if hadPII {
		r.lifePIIRedacted++
	}
	if e.Verdict == VerdictBlockedDLP || e.Verdict == VerdictBlockedPolicy {
		if e.InjectionScore > 0 {
			r.lifeInjectionsBlocked++
		}
	}
}

// Recent returns up to `n` most-recent entries, newest first.
func (r *Recorder) Recent(n int) []Entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n <= 0 || n > r.capacity {
		n = r.capacity
	}
	// Count non-empty slots so we never re-visit past the ring's edge.
	buffered := 0
	for _, e := range r.entries {
		if !e.Timestamp.IsZero() {
			buffered++
		}
	}
	if buffered < n {
		n = buffered
	}
	out := make([]Entry, 0, n)
	idx := r.head - 1
	if idx < 0 {
		idx += r.capacity
	}
	for i := 0; i < n; i++ {
		out = append(out, r.entries[idx])
		idx--
		if idx < 0 {
			idx += r.capacity
		}
	}
	return out
}

// Stats surfaces summary counters for the dashboard header.
//
// The `Buffered*` fields are computed from the ring-buffer window.
// The `Lifetime*` fields are monotonic since process start and back
// the Brave-style tiles on the dashboard.
type Stats struct {
	Total          uint64
	Allowed        int
	Redacted       int
	Warned         int
	BlockedDLP     int
	BlockedPolicy  int
	UpstreamErrors int
	AuthFailures   int
	Errors         int
	Buffered       int
	Capacity       int

	LifetimeSecretsCaught     uint64
	LifetimePIIRedacted       uint64
	LifetimeInjectionsBlocked uint64
}

// Stats returns aggregated counts over the buffered window.
func (r *Recorder) Stats() Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := Stats{
		Total:                     r.total,
		Capacity:                  r.capacity,
		LifetimeSecretsCaught:     r.lifeSecretsCaught,
		LifetimePIIRedacted:       r.lifePIIRedacted,
		LifetimeInjectionsBlocked: r.lifeInjectionsBlocked,
	}
	for _, e := range r.entries {
		if e.Timestamp.IsZero() {
			continue
		}
		s.Buffered++
		switch e.Verdict {
		case VerdictAllowed:
			s.Allowed++
		case VerdictRedacted:
			s.Redacted++
		case VerdictWarned:
			s.Warned++
		case VerdictBlockedDLP:
			s.BlockedDLP++
		case VerdictBlockedPolicy:
			s.BlockedPolicy++
		case VerdictAuthFailed:
			s.AuthFailures++
		case VerdictUpstreamError:
			s.UpstreamErrors++
		default:
			s.Errors++
		}
	}
	return s
}

// EstimatedTimeSaved is the vanity tile heuristic. It assumes each
// caught secret would have cost ~5 minutes of incident-response time
// (rotation, notification, log audit) and each blocked injection ~15
// minutes (dependent on downstream blast radius). Numbers are labels,
// not a promise — the copy on the tile makes that clear.
func (s Stats) EstimatedTimeSaved() time.Duration {
	const secretCost = 5 * time.Minute
	const injectionCost = 15 * time.Minute
	return time.Duration(s.LifetimeSecretsCaught)*secretCost +
		time.Duration(s.LifetimeInjectionsBlocked)*injectionCost
}

// VerdictFromError classifies a canonical error into a Verdict.
// Used by the engine when constructing an Entry after a request completes.
func VerdictFromError(err error, hadFindings bool, hadWarnings bool) Verdict {
	if err == nil {
		if hadFindings {
			return VerdictRedacted
		}
		if hadWarnings {
			return VerdictWarned
		}
		return VerdictAllowed
	}
	if isAny(err, api.ErrDLPBlocked) {
		return VerdictBlockedDLP
	}
	if isAny(err, api.ErrPolicyBlocked, api.ErrDLPRedaction) {
		return VerdictBlockedPolicy
	}
	if isAny(err, api.ErrAuthFailed) {
		return VerdictAuthFailed
	}
	if isAny(err, api.ErrUnavailable, api.ErrProvider, api.ErrRateLimit) {
		return VerdictUpstreamError
	}
	return VerdictError
}

func isAny(err error, targets ...error) bool {
	for _, t := range targets {
		if err != nil && errorsIs(err, t) {
			return true
		}
	}
	return false
}
