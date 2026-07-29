package main

import "regexp"

// Local mirror of internal/dlp/patterns/patterns.go so the desktop binary
// is self-contained (no dependency on the policyd module). Keep in sync
// when adding new patterns on the server side.

type Finding struct {
	Kind  string
	Start int
	End   int
	Text  string
}

var (
	reSSN         = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	reCC          = regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`)
	reEmail       = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b`)
	reAPIKey      = regexp.MustCompile(`\b(?:sk|pk|api[_-]?key|token|secret)[_-][A-Za-z0-9\-]{16,64}\b`)
	reAWSKey      = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	reGitHubToken = regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b`)
	rePrivateKey  = regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`)
)

// scan runs every pattern against the input. Findings are returned in
// discovery order; consumers should sort by Start if they need positional
// ordering.
func scan(input string) []Finding {
	var out []Finding
	add := func(kind string, re *regexp.Regexp, validate func(string) bool) {
		for _, m := range re.FindAllStringIndex(input, -1) {
			raw := input[m[0]:m[1]]
			if validate != nil && !validate(raw) {
				continue
			}
			out = append(out, Finding{Kind: kind, Start: m[0], End: m[1], Text: raw})
		}
	}
	add("ssn", reSSN, nil)
	add("credit_card", reCC, isLuhnValid)
	add("email", reEmail, nil)
	add("api_key", reAPIKey, nil)
	add("aws_key", reAWSKey, nil)
	add("github_token", reGitHubToken, nil)
	add("private_key", rePrivateKey, nil)
	return out
}

func isLuhnValid(raw string) bool {
	digits := make([]int, 0, len(raw))
	for _, r := range raw {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum, alt := 0, false
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
