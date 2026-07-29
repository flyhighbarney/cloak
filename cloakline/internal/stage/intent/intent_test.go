package intent

import (
	"strings"
	"testing"
)

func TestLooksIntentionalPositives(t *testing.T) {
	cases := []struct {
		text  string
		match string
	}{
		{"my password is hunter2 please help me reset it", "hunter2"},
		{"here's my API key AKIA0123456789ABCDEF", "AKIA0123456789ABCDEF"},
		{"the password is xkj29Djs, help me log in", "xkj29Djs"},
		{"credentials: username=foo pass=bar", "bar"},
		{"login: alice\npassword: hunter2", "hunter2"},
		{"my credit card is 4111 1111 1111 1111 and I want to pay", "4111 1111 1111 1111"},
	}
	for _, c := range cases {
		t.Run(c.text[:min(30, len(c.text))], func(t *testing.T) {
			s := strings.Index(c.text, c.match)
			if s < 0 {
				t.Fatalf("match %q not found in text", c.match)
			}
			if !LooksIntentional(c.text, s, s+len(c.match)) {
				t.Errorf("expected LooksIntentional true for %q", c.text)
			}
		})
	}
}

func TestLooksIntentionalNegatives(t *testing.T) {
	// These contain a credential-shaped string but no intent phrase.
	cases := []struct {
		text  string
		match string
	}{
		{"here is a log line with random hex AKIA0123456789ABCDEF spilled", "AKIA0123456789ABCDEF"},
		{"the ticket references 4111111111111111 in the description", "4111111111111111"},
		{"a random string sk-ant-abcd1234efgh5678ijkl appears mid-paragraph", "sk-ant-abcd1234efgh5678ijkl"},
	}
	for _, c := range cases {
		t.Run(c.text[:min(30, len(c.text))], func(t *testing.T) {
			s := strings.Index(c.text, c.match)
			if s < 0 {
				t.Fatalf("setup: match not found")
			}
			if LooksIntentional(c.text, s, s+len(c.match)) {
				t.Errorf("expected LooksIntentional false for %q", c.text)
			}
		})
	}
}

func TestFindPasswordCandidates(t *testing.T) {
	text := "password: hunter2\nother stuff\npass = secretPass1\npw:  short"
	got := FindPasswordCandidates(text)
	if len(got) != 3 {
		t.Fatalf("got %d candidates, want 3: %v", len(got), got)
	}
	// First hit is "hunter2".
	if v := text[got[0][0]:got[0][1]]; v != "hunter2" {
		t.Errorf("first candidate = %q, want hunter2", v)
	}
	if v := text[got[1][0]:got[1][1]]; v != "secretPass1" {
		t.Errorf("second candidate = %q, want secretPass1", v)
	}
	if v := text[got[2][0]:got[2][1]]; v != "short" {
		t.Errorf("third candidate = %q, want short", v)
	}
}

func TestFindPasswordCandidatesSkipsPlaceholders(t *testing.T) {
	// Real passwords are one thing; obvious placeholders shouldn't fire.
	text := "password: xxx\npassword: <redacted>\npassword: [REDACTED]"
	got := FindPasswordCandidates(text)
	if len(got) != 0 {
		t.Fatalf("placeholders should not fire, got %v", got)
	}
}

func TestLooksIntentionalBoundsSafe(t *testing.T) {
	// Guards against negative / out-of-range indices.
	if LooksIntentional("abc", -1, 2) {
		t.Error("negative start should be safe (return false or clamp)")
	}
	if LooksIntentional("abc", 0, 999) {
		t.Error("out-of-range end should be safe")
	}
	if LooksIntentional("", 0, 0) {
		t.Error("empty text should not fire")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
