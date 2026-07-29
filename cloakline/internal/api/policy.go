package api

import "context"

// PolicyKind partitions the policy namespace by purpose.
type PolicyKind string

const (
	PolicyKindRouting PolicyKind = "routing"
	PolicyKindDLP     PolicyKind = "dlp"
	PolicyKindBudget  PolicyKind = "budget"
)

// Policy is a compiled CEL program.
type Policy interface {
	ID() PolicyRuleID
	Kind() PolicyKind
	RequiredEnvKeys() []string
}

// PolicyEnv is the map of variable bindings a Policy evaluates against.
// The concrete shape is dictated by the policy kind — see docs/policy-language.md.
type PolicyEnv map[string]any

// PolicyResult is a policy engine's raw return, prior to interpretation.
type PolicyResult struct {
	Kind    PolicyKind
	Value   any    // engine-defined per PolicyKind
	TraceID PolicyRuleID
}

// PolicyEngine compiles and evaluates policies.
type PolicyEngine interface {
	APIVersion() string
	Compile(source string, kind PolicyKind, id PolicyRuleID) (Policy, error)
	Eval(ctx context.Context, p Policy, env PolicyEnv) (PolicyResult, error)
}
