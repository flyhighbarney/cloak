package tlsinspect

import (
	"strings"
	"testing"
	"time"
)

func TestForwardLogLimiter_FirstEmitsThenFolds(t *testing.T) {
	l := newForwardLogLimiter(10 * time.Second)
	base := time.Unix(0, 0)

	// First occurrence emits immediately with count 1.
	emit, count := l.record(base, "k")
	if !emit || count != 1 {
		t.Fatalf("first record: emit=%v count=%d, want true/1", emit, count)
	}

	// Subsequent occurrences inside the window are folded (suppressed).
	for i := 1; i <= 5; i++ {
		if emit, _ := l.record(base.Add(time.Duration(i)*time.Second), "k"); emit {
			t.Fatalf("record at +%ds emitted; want suppressed", i)
		}
	}

	// The next event at/after the window boundary emits and reports every
	// occurrence folded since the last emit (the 5 suppressed + this one).
	emit, count = l.record(base.Add(11*time.Second), "k")
	if !emit || count != 6 {
		t.Fatalf("window-boundary record: emit=%v count=%d, want true/6", emit, count)
	}
}

func TestForwardLogLimiter_KeysAreIndependent(t *testing.T) {
	l := newForwardLogLimiter(10 * time.Second)
	base := time.Unix(0, 0)

	if emit, count := l.record(base, "a"); !emit || count != 1 {
		t.Fatalf("key a first: emit=%v count=%d, want true/1", emit, count)
	}
	// A different key is tracked separately and also emits its first event.
	if emit, count := l.record(base, "b"); !emit || count != 1 {
		t.Fatalf("key b first: emit=%v count=%d, want true/1", emit, count)
	}
}

func TestCoarsePath(t *testing.T) {
	cases := map[string]string{
		"/api/eval/sdk-zAZezfDKGoZuXXKe": "/api/eval",
		"/api/claude_cli/bootstrap":      "/api/claude_cli",
		"/mcp-registry/v0/servers":       "/mcp-registry/v0",
		"/api/hello":                     "/api/hello",
		"/api":                           "/api",
		"/":                              "/",
		"":                               "/",
	}
	for in, want := range cases {
		if got := coarsePath(in); got != want {
			t.Errorf("coarsePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSummarizeKinds(t *testing.T) {
	if got := summarizeKinds(nil); got != "" {
		t.Errorf("empty map = %q, want \"\"", got)
	}
	// Deterministic (sorted) output regardless of map iteration order.
	got := summarizeKinds(map[string]int{"password": 1, "email": 4, "url_path": 3140})
	want := "email=4,password=1,url_path=3140"
	if got != want {
		t.Errorf("summarizeKinds = %q, want %q", got, want)
	}
	// The matched plaintext is never part of the output — only kind + count.
	if strings.Contains(summarizeKinds(map[string]int{"password": 1}), "=") == false {
		t.Error("expected kind=count form")
	}
}

// Two random eval paths must land in the same dedup bucket, so the second is
// folded rather than emitted — this is what keeps the /api/eval/sdk-<random>
// storm from defeating the limiter.
func TestForwardLogLimiter_CoarsePathCollapsesRandomSuffixes(t *testing.T) {
	l := newForwardLogLimiter(10 * time.Second)
	base := time.Unix(0, 0)

	k1 := "tlsinspect.passthrough_failed|api.anthropic.com|" + coarsePath("/api/eval/sdk-AAA") + "|canceled"
	k2 := "tlsinspect.passthrough_failed|api.anthropic.com|" + coarsePath("/api/eval/sdk-BBB") + "|canceled"
	if k1 != k2 {
		t.Fatalf("coarse keys differ: %q vs %q", k1, k2)
	}
	if emit, _ := l.record(base, k1); !emit {
		t.Fatal("first eval path should emit")
	}
	if emit, _ := l.record(base.Add(time.Second), k2); emit {
		t.Fatal("second eval path (random suffix) should be folded, not emitted")
	}
}
