package http

import (
	"math"
	"sync"
	"time"
)

// tokenBucket is a per-key token-bucket limiter. Refill happens lazily on
// every consume(); no background goroutine needed.
type tokenBucket struct {
	rate  float64 // tokens per second
	burst float64 // capacity

	mu      sync.Mutex
	buckets map[string]*bucketState
}

type bucketState struct {
	tokens float64
	last   time.Time
}

// newTokenBucket returns a limiter with `perSecond` refill and `burst` capacity.
func newTokenBucket(perSecond, burst float64) *tokenBucket {
	if perSecond <= 0 {
		perSecond = 100
	}
	if burst <= 0 {
		burst = perSecond
	}
	return &tokenBucket{
		rate:    perSecond,
		burst:   burst,
		buckets: make(map[string]*bucketState),
	}
}

// allow consumes one token for `key`. Returns true if allowed, false if empty.
// retryAfter is the seconds until at least one token becomes available.
func (t *tokenBucket) allow(key string) (ok bool, retryAfter float64) {
	if t == nil {
		return true, 0
	}
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()

	b, exists := t.buckets[key]
	if !exists {
		b = &bucketState{tokens: t.burst, last: now}
		t.buckets[key] = b
	} else {
		// Refill lazily.
		elapsed := now.Sub(b.last).Seconds()
		b.tokens = math.Min(t.burst, b.tokens+elapsed*t.rate)
		b.last = now
	}
	if b.tokens < 1 {
		wait := (1 - b.tokens) / t.rate
		return false, wait
	}
	b.tokens--
	return true, 0
}

// prune removes stale entries. Callers should invoke this periodically or
// on process signal; not strictly required for correctness.
func (t *tokenBucket) prune(maxAge time.Duration) {
	if t == nil {
		return
	}
	cutoff := time.Now().Add(-maxAge)
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, b := range t.buckets {
		if b.last.Before(cutoff) {
			delete(t.buckets, k)
		}
	}
}
