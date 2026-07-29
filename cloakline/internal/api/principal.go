package api

import "time"

// Principal is the resolved identity of a request. Immutable once created.
// Never construct from user input directly — auth package produces these
// from validated virtual keys.
type Principal struct {
	APIVersion    string
	TenantID      TenantID
	KeyID         KeyID
	Scopes        []Scope
	BudgetRef     BudgetRef
	RoutingPolicy PolicyRef
	Expiry        time.Time // zero = never
	AuditID       AuditID
	Metadata      map[string]string // no security semantics
}

// HasScope reports whether the principal holds the given scope.
func (p Principal) HasScope(s Scope) bool {
	for _, x := range p.Scopes {
		if x == s {
			return true
		}
	}
	return false
}

// Expired reports whether the principal has passed its expiry.
func (p Principal) Expired(now time.Time) bool {
	if p.Expiry.IsZero() {
		return false
	}
	return now.After(p.Expiry)
}
