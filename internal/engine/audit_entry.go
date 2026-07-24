package engine

import (
	"context"
	"time"

	"policyd/internal/api"
	"policyd/internal/audit"
	"policyd/internal/obs/log"
	"policyd/internal/stage/dlptier1"
	"policyd/internal/stage/injection"
)

// buildAuditEntry projects the request state at Handle-return into a
// content-free audit entry. NEVER include plaintext content.
func buildAuditEntry(
	ctx context.Context,
	r *api.Request,
	bus api.SignalBus,
	upstream api.UpstreamID,
	model string,
	err error,
	dur time.Duration,
) audit.Entry {
	findings := extractFindingKinds(bus, dlptier1.SignalFindings)
	warnings := extractFindingKinds(bus, dlptier1.SignalWarnings)

	verdict := audit.VerdictFromError(err, len(findings) > 0, len(warnings) > 0)

	score, _ := extractInt(bus, injection.SignalScore)
	rules := extractInjectionRuleIDs(bus, injection.SignalMatchedRules)

	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}

	return audit.Entry{
		Timestamp:      time.Now().UTC(),
		RequestID:      string(r.ID),
		TenantID:       string(r.Principal.TenantID),
		KeyID:          string(r.Principal.KeyID),
		Endpoint:       log.EndpointFrom(ctx),
		Mode:           r.Mode.String(),
		Upstream:       string(upstream),
		Model:          model,
		Verdict:        verdict,
		DLPFindings:    findings,
		InjectionScore: score,
		InjectionRules: rules,
		DurationMS:     dur.Milliseconds(),
		Error:          errMsg,
	}
}

func extractFindingKinds(bus api.SignalBus, name api.SignalName) []string {
	v, ok := bus.Get(name)
	if !ok || v == nil {
		return nil
	}
	fs, ok := v.([]dlptier1.Finding)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, string(f.Kind))
	}
	return out
}

func extractInjectionRuleIDs(bus api.SignalBus, name api.SignalName) []string {
	v, ok := bus.Get(name)
	if !ok || v == nil {
		return nil
	}
	ms, ok := v.([]injection.Match)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.RuleID)
	}
	return out
}

func extractInt(bus api.SignalBus, name api.SignalName) (int, bool) {
	v, ok := bus.Get(name)
	if !ok {
		return 0, false
	}
	i, ok := v.(int)
	return i, ok
}
