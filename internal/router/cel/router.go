// Package cel implements api.Router as a chain of CEL policies evaluated
// against an immutable RouteSnapshot. Pure function of (Request, Snapshot).
package cel

import (
	"context"
	"fmt"

	"policyd/internal/api"
)

const APIVersion = api.RouterAPIVersion

// Router runs a list of routing policies in order until one returns a valid
// UpstreamID that appears in the snapshot's candidate set.
type Router struct {
	engine   api.PolicyEngine
	policies []api.Policy
}

func New(engine api.PolicyEngine, policies []api.Policy) *Router {
	return &Router{engine: engine, policies: policies}
}

func (r *Router) APIVersion() string { return APIVersion }

func (r *Router) Select(ctx context.Context, req *api.Request, snap api.RouteSnapshot) (api.RouteDecision, error) {
	if len(snap.Candidates) == 0 {
		return api.RouteDecision{}, fmt.Errorf("%w: no candidates in snapshot", api.ErrCapMismatch)
	}
	env := buildEnv(req, snap)
	var trace []api.PolicyRuleID
	var lastEvalErr error
	var lastValueType string
	for _, p := range r.policies {
		res, err := r.engine.Eval(ctx, p, env)
		trace = append(trace, p.ID())
		if err != nil {
			lastEvalErr = err
			continue // try next policy
		}
		lastValueType = fmt.Sprintf("%T", res.Value)
		up, reason, ok := interpret(res.Value, snap)
		if !ok {
			continue
		}
		return api.RouteDecision{Upstream: up, Reason: reason, Trace: trace}, nil
	}
	if lastEvalErr != nil {
		return api.RouteDecision{Trace: trace},
			fmt.Errorf("%w: policy eval err=%v", api.ErrCapMismatch, lastEvalErr)
	}
	return api.RouteDecision{Trace: trace},
		fmt.Errorf("%w: no policy produced a valid upstream (last value type: %s)",
			api.ErrCapMismatch, lastValueType)
}

func buildEnv(r *api.Request, snap api.RouteSnapshot) api.PolicyEnv {
	textCharCount := 0
	modalities := make(map[string]bool)
	totalBytes := 0
	partsCount := 0
	for _, m := range r.Messages {
		for _, p := range m.Parts {
			partsCount++
			totalBytes += len(p.Bytes)
			modalities[p.Modality.String()] = true
			if p.Modality == api.ModText {
				textCharCount += len(p.Bytes)
			}
		}
	}
	modList := make([]string, 0, len(modalities))
	for k := range modalities {
		modList = append(modList, k)
	}
	toolNames := make([]string, 0, len(r.Tools))
	for _, t := range r.Tools {
		toolNames = append(toolNames, t.Name)
	}
	candidates := make([]map[string]any, len(snap.Candidates))
	for i, c := range snap.Candidates {
		candidates[i] = map[string]any{
			"id":            string(c.ID),
			"kind":          string(c.Kind),
			"health":        c.Health.String(),
			"streaming":     streamCapsToString(c.Caps.Streaming),
			"max_context":   c.Caps.MaxContext,
			"cost_per_1k_in":  c.Cost.CostPer1KIn,
			"cost_per_1k_out": c.Cost.CostPer1KOut,
			"error_rate":    c.Cost.RecentErrorRate,
			"queue_depth":   int(c.Queue),
			"caps": map[string]any{
				"modalities":  modalitiesList(c.Caps.Modalities),
				"streaming":   streamCapsToString(c.Caps.Streaming),
				"max_context": c.Caps.MaxContext,
			},
		}
	}
	// Extract the client-requested model from whichever provider extension
	// the transport populated. Empty when neither is set.
	model := ""
	if ext, ok := r.Extensions.OpenAI(); ok && ext.Model != "" {
		model = ext.Model
	} else if ext, ok := r.Extensions.Anthropic(); ok && ext.Model != "" {
		model = ext.Model
	}
	return api.PolicyEnv{
		"request": map[string]any{
			"id":              string(r.ID),
			"mode":            r.Mode.String(),
			"model":           model,
			"modalities":      modList,
			"parts_count":     partsCount,
			"total_bytes":     totalBytes,
			"text_char_count": textCharCount,
			"has_tools":       len(r.Tools) > 0,
			"tool_names":      toolNames,
		},
		"principal": map[string]any{
			"tenant_id":         string(r.Principal.TenantID),
			"scopes":            scopesList(r.Principal.Scopes),
			"routing_policy_id": string(r.Principal.RoutingPolicy),
		},
		"snapshot": map[string]any{
			"taken_at":   snap.TakenAt.Unix(),
			"candidates": candidates,
		},
	}
}

func interpret(v any, snap api.RouteSnapshot) (api.UpstreamID, string, bool) {
	// A valid verdict may be a map (from a CEL RouteVerdict literal) or a
	// raw string upstream_id.
	switch x := v.(type) {
	case map[string]any:
		id, _ := x["upstream_id"].(string)
		reason, _ := x["reason"].(string)
		if id == "" {
			return "", "", false
		}
		if !inCandidates(api.UpstreamID(id), snap) {
			return "", "", false
		}
		return api.UpstreamID(id), reason, true
	case string:
		if !inCandidates(api.UpstreamID(x), snap) {
			return "", "", false
		}
		return api.UpstreamID(x), "policy-string-verdict", true
	}
	return "", "", false
}

func inCandidates(id api.UpstreamID, snap api.RouteSnapshot) bool {
	for _, c := range snap.Candidates {
		if c.ID == id {
			return true
		}
	}
	return false
}

func modalitiesList(s api.ModalitySet) []string {
	out := make([]string, 0)
	for _, m := range s.Modalities() {
		out = append(out, m.String())
	}
	return out
}

func scopesList(s []api.Scope) []string {
	out := make([]string, len(s))
	for i, sc := range s {
		out[i] = string(sc)
	}
	return out
}

func streamCapsToString(s api.StreamCaps) string {
	switch s {
	case api.StreamSSE:
		return "sse"
	case api.StreamWSFrames:
		return "ws"
	}
	return "none"
}
