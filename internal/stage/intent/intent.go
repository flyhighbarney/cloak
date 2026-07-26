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
	return findLabelledValues(text, rePasswordCandidates, 3, false)
}

// FindSecretCandidates returns [start,end) offsets of values that follow
// an API-key / token / secret label ("api key: X", "token = X", "the
// secret is X", "Authorization: Bearer X"). Like passwords, these values
// often have no vendor-specific shape (a plain UUID, a hand-typed token),
// so the LABEL is the detector. Callers should treat every returned range
// as a high-tier credential (one-way redact), same as a raw API key.
//
// The minimum value length is higher than for passwords (>= 6) and the
// value must "look secret-ish" (contain a digit, a symbol, or be long) so
// natural prose like "the token is invalid" doesn't redact the word after.
func FindSecretCandidates(text string) [][2]int {
	return findLabelledValues(text, reSecretCandidates, 6, true)
}

// FindLabelledSSNCandidates returns [start,end) offsets of 9-digit runs
// that follow an SSN / social-security label, covering the no-separator
// form ("ssn: 123456789") that the shape-based SSN regex deliberately
// skips. The returned range is the digit run only.
func FindLabelledSSNCandidates(text string) [][2]int {
	var out [][2]int
	seen := make(map[[2]int]struct{})
	for _, m := range reLabelledSSN.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 4 {
			continue
		}
		vs, ve := m[2], m[3]
		if vs < 0 || ve <= vs {
			continue
		}
		r := [2]int{vs, ve}
		if _, dup := seen[r]; dup {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	return out
}

// findLabelledValues is the shared engine behind the label-based detectors.
// It runs each regex (submatch 1 = the value), enforces a minimum length,
// drops obvious placeholders, optionally requires the value to look
// "secret-ish", and de-dupes overlapping hits.
func findLabelledValues(text string, res []*regexp.Regexp, minLen int, requireSecretish bool) [][2]int {
	var out [][2]int
	seen := make(map[[2]int]struct{})
	for _, re := range res {
		for _, m := range re.FindAllStringSubmatchIndex(text, -1) {
			if len(m) < 4 {
				continue
			}
			vs, ve := m[2], m[3]
			if vs < 0 || ve <= vs {
				continue
			}
			val := text[vs:ve]
			if len(val) < minLen {
				continue
			}
			if isPlaceholder(val) {
				continue
			}
			if requireSecretish && !looksSecretish(val) {
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

// isPlaceholder rejects redaction markers and template stand-ins that a
// user pastes as an EXAMPLE rather than a real secret.
func isPlaceholder(val string) bool {
	lower := strings.ToLower(val)
	switch lower {
	case "xxx", "***", "<redacted>", "your_key_here", "your-api-key", "null", "none":
		return true
	}
	return strings.HasPrefix(lower, "[") || strings.HasPrefix(lower, "<") ||
		strings.HasPrefix(lower, "your_") || strings.HasPrefix(lower, "your-")
}

// looksSecretish is a cheap gate that a real key/token almost always
// passes but an ordinary English word does not: it contains a digit, or a
// key-ish symbol (_ - . /), or is long, or mixes upper- and lower-case.
func looksSecretish(val string) bool {
	if len(val) >= 16 {
		return true
	}
	hasDigit, hasUpper, hasLower, hasSym := false, false, false, false
	for _, r := range val {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r == '_' || r == '-' || r == '.' || r == '/':
			hasSym = true
		}
	}
	return hasDigit || hasSym || (hasUpper && hasLower)
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
		// Labelled block: "password: X", "pw=X", "psd : X", "pwd -> X".
		// The label + a delimiter is the signal; the value runs to
		// whitespace/EOL. Delimiters cover the punctuation people actually
		// type: colon, equals, dash, and arrows.
		regexp.MustCompile(`(?i)\b(?:passwords?|passwd|passcode|passphrase|pwd|pword|p/w|pw|psd|pass)\s*(?:[:=\-]|->|=>|→)\s*(\S{3,})`),
		// Verb form: "password is X", "my pass was X". No delimiter, so the
		// value is the next whitespace-delimited token. Erring toward an
		// extra redact is safe per this package's design.
		regexp.MustCompile(`(?i)\b(?:password|passwd|passcode|passphrase|pwd|pass)\s+(?:is|was|=)\s+(\S{3,})`),
	}

	// reSecretCandidates capture an API-key / token / secret VALUE in
	// submatch 1. FindSecretCandidates runs them all and merges the hits.
	reSecretCandidates = []*regexp.Regexp{
		// "api key: X", "api_key = X", "apikey -> X", "my api key is X".
		regexp.MustCompile(`(?i)\bapi[\s_\-]?key\b\s*(?:[:=\-]|->|=>|→|\bis\b|\bwas\b)\s*(\S{6,})`),
		// "token: X", "access token = X", "auth token is X".
		regexp.MustCompile(`(?i)\b(?:access|auth|refresh|bearer)?[\s_\-]?token\b\s*(?:[:=\-]|->|=>|→|\bis\b|\bwas\b)\s*(\S{6,})`),
		// "secret: X", "client secret = X", "the secret is X".
		regexp.MustCompile(`(?i)\b(?:client[\s_\-]?)?secret(?:[\s_\-]?key)?\b\s*(?:[:=\-]|->|=>|→|\bis\b|\bwas\b)\s*(\S{6,})`),
		// Bearer header form with no colon: "Authorization: Bearer eyJ...".
		regexp.MustCompile(`(?i)\bbearer\s+([A-Za-z0-9_\-\.]{8,})`),
	}

	// reLabelledSSN captures a 9-digit SSN VALUE (submatch 1) after a
	// social-security label, including the no-separator form.
	reLabelledSSN = regexp.MustCompile(`(?i)\b(?:ssn|social(?:\s*security)?(?:\s*(?:number|no|#))?)\b\s*(?:[:=\-#]|->|=>|→|\bis\b)?\s*(\d{3}[- ]?\d{2}[- ]?\d{4})\b`)
)
