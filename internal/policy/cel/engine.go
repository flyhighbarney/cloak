// Package cel wraps google/cel-go with typed environments per policy kind.
//
// See docs/policy-language.md for the variable and function vocabulary.
package cel

import (
	"context"
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"

	"cloakline/internal/api"
)

const APIVersion = api.PolicyEngineAPIVersion

// Engine is the CEL PolicyEngine implementation.
type Engine struct {
	routing *cel.Env
}

// NewEngine builds the CEL environment with the routing variables and helpers.
func NewEngine() (*Engine, error) {
	routing, err := cel.NewEnv(
		cel.Variable("request", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("snapshot", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("principal", cel.MapType(cel.StringType, cel.DynType)),
		// Helper: supports_streaming(u) -> bool
		cel.Function("supports_streaming",
			cel.Overload("supports_streaming_map",
				[]*cel.Type{cel.MapType(cel.StringType, cel.DynType)},
				cel.BoolType,
				cel.UnaryBinding(func(u ref.Val) ref.Val {
					m, ok := u.(interface {
						Get(k ref.Val) ref.Val
					})
					if !ok {
						return types.False
					}
					v := m.Get(types.String("streaming"))
					s, ok := v.Value().(string)
					if !ok {
						return types.False
					}
					if s == "sse" || s == "ws" {
						return types.True
					}
					return types.False
				}),
			),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("cel env: %w", err)
	}
	return &Engine{routing: routing}, nil
}

func (e *Engine) APIVersion() string { return APIVersion }

// Compile compiles a CEL expression under the environment for kind.
func (e *Engine) Compile(source string, kind api.PolicyKind, id api.PolicyRuleID) (api.Policy, error) {
	env, err := e.envFor(kind)
	if err != nil {
		return nil, err
	}
	ast, iss := env.Compile(source)
	if iss != nil && iss.Err() != nil {
		return nil, fmt.Errorf("compile %s: %w", id, iss.Err())
	}
	prg, err := env.Program(ast, cel.CostLimit(10000))
	if err != nil {
		return nil, fmt.Errorf("program %s: %w", id, err)
	}
	return &compiledPolicy{id: id, kind: kind, prg: prg}, nil
}

// Eval runs a compiled policy against env.
func (e *Engine) Eval(ctx context.Context, p api.Policy, env api.PolicyEnv) (api.PolicyResult, error) {
	cp, ok := p.(*compiledPolicy)
	if !ok {
		return api.PolicyResult{}, fmt.Errorf("%w: policy not from this engine", api.ErrPolicyBlocked)
	}
	// cel-go's ContextEval rejects named map types; feed it the underlying map.
	activation := map[string]any(env)
	out, _, err := cp.prg.ContextEval(ctx, activation)
	if err != nil {
		return api.PolicyResult{}, fmt.Errorf("eval %s: %w", cp.id, err)
	}
	return api.PolicyResult{
		Kind:    cp.kind,
		Value:   out.Value(),
		TraceID: cp.id,
	}, nil
}

func (e *Engine) envFor(kind api.PolicyKind) (*cel.Env, error) {
	switch kind {
	case api.PolicyKindRouting:
		return e.routing, nil
	}
	return nil, fmt.Errorf("%w: kind %q has no environment", api.ErrConfigInvalid, kind)
}

type compiledPolicy struct {
	id   api.PolicyRuleID
	kind api.PolicyKind
	prg  cel.Program
}

func (p *compiledPolicy) ID() api.PolicyRuleID       { return p.id }
func (p *compiledPolicy) Kind() api.PolicyKind       { return p.kind }
func (p *compiledPolicy) RequiredEnvKeys() []string  { return nil }
