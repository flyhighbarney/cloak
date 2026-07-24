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
	}
	return DLPActionUnknown
}
