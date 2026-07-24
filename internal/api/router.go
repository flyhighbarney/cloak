package api

import (
	"context"
	"time"
)

// HealthState is the point-in-time health of an Upstream.
type HealthState uint8

const (
	HealthUnknown     HealthState = 0
	HealthHealthy     HealthState = 1
	HealthDegraded    HealthState = 2
	HealthCold        HealthState = 3 // local model, not resident
	HealthUnavailable HealthState = 4
)

func (h HealthState) String() string {
	switch h {
	case HealthHealthy:
		return "healthy"
	case HealthDegraded:
		return "degraded"
	case HealthCold:
		return "cold"
	case HealthUnavailable:
		return "unavailable"
	}
	return "unknown"
}

// QueueDepth is a coarse in-flight-request count.
type QueueDepth int

// BudgetView is a read-only projection of budget state at snapshot time.
type BudgetView struct {
	Remaining map[BudgetRef]float64 // dollars; -1 means unlimited
}

// RecentDecisions is a rolling recent history for round-robin / fairness policies.
type RecentDecisions struct {
	Last []UpstreamID // most-recent-last
}

// CostView is per-upstream cost estimates surfaced to routing policies.
type CostView struct {
	CostPer1KIn      float64
	CostPer1KOut     float64
	RecentErrorRate  float64 // 0.0–1.0
}

// UpstreamSnapshot is the per-upstream frozen view visible to a policy.
type UpstreamSnapshot struct {
	ID       UpstreamID
	Kind     UpstreamKind
	Health   HealthState
	Caps     Caps
	Queue    QueueDepth
	Cost     CostView
}

// RouteSnapshot is the immutable input to Router.Select. Same input → same output.
type RouteSnapshot struct {
	TakenAt    time.Time
	Candidates []UpstreamSnapshot
	Budgets    BudgetView
	History    RecentDecisions
}

// RouteDecision is the router's output.
type RouteDecision struct {
	Upstream UpstreamID
	Reason   string
	Trace    []PolicyRuleID
}

// Router is a pure function of (Request, Snapshot) → Decision.
// No live queries. No wall-clock reads other than snap.TakenAt.
type Router interface {
	APIVersion() string
	Select(ctx context.Context, r *Request, snap RouteSnapshot) (RouteDecision, error)
}
