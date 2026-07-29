package api

// DLPAction is what a DLP stage does when a finding hits.
// Actions apply per finding kind (SSN, credit card, email, etc.).
type DLPAction uint8

const (
	DLPActionUnknown DLPAction = 0
	// Allow lets the content pass unmodified. No log entry, no metric label.
	DLPActionAllow DLPAction = 1
	// Warn tokenizes the content (like Redact) AND emits a warning event.
	// The upstream still sees the redacted form. Used when you want an audit
	// trail without blocking a workflow.
	DLPActionWarn DLPAction = 2
	// Redact tokenizes the content transparently — the upstream sees a
	// pseudonym; the client's response is de-anonymized on the return path.
	DLPActionRedact DLPAction = 3
	// Block rejects the request with ErrDLPBlocked. No upstream call is made.
	DLPActionBlock DLPAction = 4
	// RedactOneWay replaces the matched text with a static per-kind marker
	// (e.g. "[REDACTED_API_KEY]"). The plaintext is NEVER written to the
	// session vault, NEVER logged, and is NOT restored on the response —
	// the marker remains visible in the model's reply so the user knows
	// their credential was masked. Used for credential-shaped kinds
	// (api_key, aws_key, github_token, private_key) that must never leak
	// but should not hard-block the request.
	DLPActionRedactOneWay DLPAction = 5
)

func (a DLPAction) String() string {
	switch a {
	case DLPActionAllow:
		return "allow"
	case DLPActionWarn:
		return "warn"
	case DLPActionRedact:
		return "redact"
	case DLPActionBlock:
		return "block"
	case DLPActionRedactOneWay:
		return "redact_one_way"
	}
	return "unknown"
}

// ParseDLPAction accepts strings from config files.
func ParseDLPAction(s string) DLPAction {
	switch s {
	case "allow":
		return DLPActionAllow
	case "warn":
		return DLPActionWarn
	case "redact":
		return DLPActionRedact
	case "block":
		return DLPActionBlock
	case "redact_one_way", "mask", "one_way":
		return DLPActionRedactOneWay
	}
	return DLPActionUnknown
}

// Tier describes the sensitivity class of a finding, used for
// dashboard badges and to decide whether intent-based confirmation
// applies. Derived from the kind — not a separate config field.
type Tier string

const (
	TierHigh   Tier = "high"   // credential-shaped; one-way redacted, may confirm
	TierMedium Tier = "medium" // PII; tokenized round-trip
	TierLow    Tier = "low"    // hostname / IP / URL; flagged only
)

// TierForKind classifies a kind. Callers use this for display and for
// deciding whether a finding should invoke the confirmation flow.
func TierForKind(kind PIIKind) Tier {
	switch kind {
	case PIIAPIKey, PIIAWSKey, PIIGitHubToken, PIIPrivateKey,
		PIICreditCard, PIIPassword:
		return TierHigh
	case PIISSN:
		return TierMedium
	case PIIEmail, PIIPhone:
		return TierLow
	case PIIIPAddress, PIIURLPath, PIIPersonName:
		return TierLow
	}
	return TierLow
}

// StaticMarkerForKind returns the fixed placeholder that RedactOneWay
// inserts in place of a matched credential. Markers are stable across
// runs (so audit entries stay readable), visible to the AI (so it can
// tell the user their content was masked), and never overlap with any
// legitimate content.
func StaticMarkerForKind(kind PIIKind) string {
	switch kind {
	case PIIAPIKey:
		return "[REDACTED_API_KEY]"
	case PIIAWSKey:
		return "[REDACTED_AWS_KEY]"
	case PIIGitHubToken:
		return "[REDACTED_GITHUB_TOKEN]"
	case PIIPrivateKey:
		return "[REDACTED_PRIVATE_KEY]"
	case PIIPassword:
		return "[REDACTED_PASSWORD]"
	case PIICreditCard:
		return "[REDACTED_CREDIT_CARD]"
	}
	return "[REDACTED]"
}
