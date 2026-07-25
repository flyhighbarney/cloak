package tlsinspect

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// forwardLogLimiter collapses repeated forward-path errors into one line per
// key per window, carrying a count, instead of emitting thousands of identical
// records. It exists because a single stall on the transparent-interception
// path (Claude Desktop cancelling and retrying every in-flight request at once
// — see docs/forward-loop-diagnosis.md) can otherwise bury a genuinely useful
// warning under a wall of duplicates.
//
// Design notes:
//   - Keying is COARSE on the path (first two segments) so high-cardinality
//     suffixes like /api/eval/sdk-<random> collapse into one bucket instead of
//     defeating the dedup and growing the map without bound.
//   - Flushing is lazy: the count for a window is reported on the first event
//     that arrives at/after the window boundary. During a storm, events keep
//     arriving, so each bucket self-flushes about once per window. The final
//     trailing batch after traffic fully stops is reported on the next event
//     (or not at all if none comes) — an acceptable cosmetic gap for a log
//     limiter, and never at the cost of the first occurrence, which is always
//     emitted immediately.
type forwardLogLimiter struct {
	window time.Duration

	mu   sync.Mutex
	seen map[string]*dedupEntry
}

type dedupEntry struct {
	windowStart time.Time
	pending     int // occurrences observed since the last emit (incl. current)
}

func newForwardLogLimiter(window time.Duration) *forwardLogLimiter {
	if window <= 0 {
		window = 10 * time.Second
	}
	return &forwardLogLimiter{
		window: window,
		seen:   make(map[string]*dedupEntry),
	}
}

// record notes one occurrence of key at time now and reports whether the caller
// should emit a log line, and if so how many occurrences that line represents
// (>=1). The first occurrence of a key always emits (count 1); subsequent ones
// within the window are folded into the next emitted line's count.
func (l *forwardLogLimiter) record(now time.Time, key string) (emit bool, count int) {
	l.mu.Lock()
	defer l.mu.Unlock()

	e := l.seen[key]
	if e == nil {
		e = &dedupEntry{}
		l.seen[key] = e
	}
	e.pending++

	if e.windowStart.IsZero() || now.Sub(e.windowStart) >= l.window {
		count = e.pending
		e.pending = 0
		e.windowStart = now
		return true, count
	}
	return false, 0
}

// errClass buckets an error so distinct failure modes never share a dedup key
// (and so a benign client cancellation is never merged with a real upstream
// failure). The classes mirror the severity split in logForwardErr.
func errClass(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	default:
		return "other"
	}
}

// coarsePath reduces a request path to at most its first two segments so that
// per-request random suffixes collapse into a single dedup bucket. Examples:
//
//	/api/eval/sdk-zAZezfDKGoZuXXKe -> /api/eval
//	/mcp-registry/v0/servers       -> /mcp-registry/v0
//	/api/hello                     -> /api/hello
func coarsePath(path string) string {
	segs := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 3)
	kept := make([]string, 0, 2)
	for _, s := range segs {
		if s == "" {
			continue
		}
		kept = append(kept, s)
		if len(kept) == 2 {
			break
		}
	}
	if len(kept) == 0 {
		return "/"
	}
	return "/" + strings.Join(kept, "/")
}

// summarizeKinds renders a detected-finding tally as a deterministic
// "kind=count,kind=count" string (sorted for stable output). It deliberately
// carries only finding KIND names and counts — never the matched plaintext —
// so it is safe to log. This is what lets a user confirm from the log that a
// "password" finding was seen (and, alongside the action tallies, that it was
// redacted) without the secret ever touching the log file.
func summarizeKinds(kinds map[string]int) string {
	if len(kinds) == 0 {
		return ""
	}
	keys := make([]string, 0, len(kinds))
	for k := range kinds {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, kinds[k]))
	}
	return strings.Join(parts, ",")
}
