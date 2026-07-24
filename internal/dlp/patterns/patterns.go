// Package patterns is the shared DLP pattern registry.
//
// Both the runtime DLP stage (internal/stage/dlptier1) and the CLI's
// standalone scanner (cmd/policyctl scan) call into this package so
// detection behavior is identical whether a finding surfaces at request
// time or during a pre-send dev-side scan.
package patterns

import (
	"regexp"

	"policyd/internal/api"
)

// Pattern is one detection rule.
type Pattern struct {
	Kind     api.PIIKind
	Regex    *regexp.Regexp
	// Validate runs an extra check on the matched substring; if nil, the
	// regex match is accepted as-is.
	Validate func(string) bool
}

// All returns the built-in Tier-1 pattern set in scan order.
// Order matters: patterns run in this sequence, and the CLI displays
// findings in this order.
func All() []Pattern {
	return []Pattern{
		{Kind: api.PIISSN, Regex: reSSN},
		{Kind: api.PIICreditCard, Regex: reCC, Validate: IsLuhnValid},
		{Kind: api.PIIEmail, Regex: reEmail},
		{Kind: api.PIIAPIKey, Regex: reGenericAPIKey},
		{Kind: api.PIIAWSKey, Regex: reAWSKey},
		{Kind: api.PIIGitHubToken, Regex: reGitHubToken},
		{Kind: api.PIIPrivateKey, Regex: rePrivateKeyHeader},
	}
}

var (
	reSSN              = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	reCC               = regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`)
	reEmail            = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b`)
	reGenericAPIKey    = regexp.MustCompile(`\b(?:sk|pk|api[_-]?key|token|secret)[_-][A-Za-z0-9\-]{16,64}\b`)
	reAWSKey           = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	reGitHubToken      = regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b`)
	rePrivateKeyHeader = regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`)
)

// IsLuhnValid strips separators from raw and applies the Luhn checksum.
// Returns false for out-of-range lengths (< 13 or > 19 digits).
func IsLuhnValid(raw string) bool {
	digits := make([]int, 0, len(raw))
	for _, r := range raw {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// Finding is a single hit produced by Scan.
type Finding struct {
	Kind  api.PIIKind
	Start int    // byte offset in the input
	End   int    // exclusive
	Text  string // matched text (never logged; caller decides how to display)
}

// Scan runs every pattern against the input and returns all findings in
// discovery order. It does NOT mutate the input and it does NOT tokenize —
// it's the pure detection surface. Callers who want redaction/tokenization
// use the DLP stage.
func Scan(input string) []Finding {
	var out []Finding
	for _, p := range All() {
		matches := p.Regex.FindAllStringIndex(input, -1)
		for _, m := range matches {
			raw := input[m[0]:m[1]]
			if p.Validate != nil && !p.Validate(raw) {
				continue
			}
			out = append(out, Finding{
				Kind:  p.Kind,
				Start: m[0],
				End:   m[1],
				Text:  raw,
			})
		}
	}
	return out
}
