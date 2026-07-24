package api

// Strongly-typed identifiers. Not aliases to string with unclear semantics —
// distinct types so the compiler catches "passed a KeyID where TenantID wanted."

type (
	RequestID    string
	SessionID    string
	TenantID     string
	KeyID        string
	AuditID      string
	BudgetRef    string
	PolicyRef    string
	PolicyRuleID string
	StageID      string
	SignalName   string
	UpstreamID   string
	MetricName   string
	DimKey       string
	Pseudonym    string
	PIIKind      string
)

// Scope is a capability grant on a Principal.
type Scope string
