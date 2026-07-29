// Package intent detects when a user has *deliberately* pasted a
// credential or card number, versus when it slipped in accidentally.
//
// The signal is textual, not statistical: a credential-shaped match
// preceded or followed by phrases like "my password is", "here's my
// key", or a structured "credentials:" block. When this signal fires
// on a HIGH-tier finding, the DLP pipeline surfaces an in-CLI
// confirmation prompt instead of silently redacting.
//
// Design constraints:
//
//   - Deterministic and fast (regex only, no ML).
//   - Conservative on false positives — if the phrase is ambiguous,
//     err on the side of "not intentional" (i.e. silent redact). The
//     user is safer with an extra silent redact than with an unwanted
//     credential leaked because we assumed intent that wasn't there.
//   - Conservative on false negatives is *also* fine — if we miss the
//     intent phrase, the credential still gets one-way redacted; the
//     user just doesn't see the y/n prompt.
package intent

import (
	"regexp"
	"strings"
)

// Window is the number of bytes to inspect on each side of a match
// when checking for an intent phrase. 80 chars covers most single-line
// "here's my password: X" style pastes without dragging in unrelated
// prose from a longer paragraph.
const Window = 80

// LooksIntentional reports whether the credential-shaped match at
// [start, end) inside text was likely pasted on purpose.
//
// The current heuristic:
//
//   - A first-person possessive naming a credential ("my password",
//     "here's my key") within Window of the match.
//   - A structured credential block ("credentials:", "login:", "user:
//     ... password: ...").
//   - Explicit meta ("this is my api key", "the token is").
//
// None of these are guarantees — they're the highest-confidence
// signals available without a model.
func LooksIntentional(text string, start, end int) bool {
	if start < 0 || end > len(text) || start > end {
		return false
	}
	lo := start - Window
	if lo < 0 {
		lo = 0
	}
	hi := end + Window
	if hi > len(text) {
		hi = len(text)
	}
	ctx := strings.ToLower(text[lo:hi])
	for _, r := range intentPhrases {
		if r.MatchString(ctx) {
			return true
		}
	}
	return false
}

// FindPasswordCandidates returns [start,end) offsets of substrings
// that look like a password value in a labelled block. A password
// has no distinctive shape of its own, so the label ("password: X",
// "pw: X", "psd: X") IS the detector. The returned range is the
// value only, not the label.
//
// Only labels followed by a plausible password (>= 3 non-whitespace
// chars, ends at whitespace or end-of-line) are returned.
func FindPasswordCandidates(text string) [][2]int {
	var out [][2]int
	seen := make(map[[2]int]struct{})
	for _, re := range rePasswordCandidates {
		for _, m := range re.FindAllStringSubmatchIndex(text, -1) {
			// Submatch 1 is the value.
			if len(m) < 4 {
				continue
			}
			vs, ve := m[2], m[3]
			if vs < 0 || ve <= vs {
				continue
			}
			val := text[vs:ve]
			if len(val) < 3 {
				continue
			}
			// Skip obvious placeholders.
			lower := strings.ToLower(val)
			if lower == "xxx" || lower == "***" || lower == "<redacted>" ||
				strings.HasPrefix(lower, "[") || strings.HasPrefix(lower, "<") {
				continue
			}
			r := [2]int{vs, ve}
			if _, dup := seen[r]; dup {
				continue
			}
			seen[r] = struct{}{}
			out = append(out, r)
		}
	}
	return out
}

var (
	// Intent phrases — case-insensitive, matched against ±Window text
	// around the credential hit.
	intentPhrases = []*regexp.Regexp{
		regexp.MustCompile(`\bmy (password|pw|pass|passcode|passphrase|key|api\s?key|token|secret|card|credit\s?card|cc)\b`),
		regexp.MustCompile(`\bhere'?s my (password|key|token|credentials?|card)\b`),
		regexp.MustCompile(`\b(the |this )?(password|key|token|api[_\s]?key|card|cc)\s*(is|=)\s*\S`),
		regexp.MustCompile(`\bcredentials?\s*:\s*`),
		regexp.MustCompile(`(?s)\b(login|user(name)?)\s*:[^\n]{0,200}\s*\n?\s*(password|pw|psd|pass)\s*:`),
	}

	// rePasswordCandidates each capture a password VALUE in submatch 1.
	// FindPasswordCandidates runs them all and merges the hits.
	rePasswordCandidates = []*regexp.Regexp{
		// Labelled block: "password: X", "pw=X", "psd : X". The label +
		// delimiter ([:=]) is the signal; the value runs to whitespace/EOL.
		regexp.MustCompile(`(?i)\b(?:password|passwd|passcode|passphrase|pw|psd|pass)\s*[:=]\s*(\S{3,})`),
		// Verb form: "password is X", "passphrase was X". No colon, so the
		// value is the next whitespace-delimited token. Full words only
		// (not pw/psd) to keep false positives down. Erring toward an extra
		// redact is safe per this package's design.
		regexp.MustCompile(`(?i)\b(?:password|passwd|passcode|passphrase)\s+(?:is|was)\s+(\S{3,})`),
	}
)
