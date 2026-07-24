package engine

import (
	"context"
	"time"

	"policyd/internal/api"
)

// Snapshotter captures immutable per-request views of Upstream state.
// It is the ONLY component in the request path allowed to read live
// subsystem state — the router receives the frozen snapshot.
type Snapshotter struct {
	upstreams []api.Upstream
	costs     map[api.UpstreamID]api.CostView
}

// NewSnapshotter returns a snapshotter over the given upstreams.
// costs supplies per-upstream cost estimates from config.
func NewSnapshotter(ups []api.Upstream, costs map[api.UpstreamID]api.CostView) *Snapshotter {
	return &Snapshotter{upstreams: ups, costs: costs}
}

// Snapshot builds a RouteSnapshot for the current instant.
func (s *Snapshotter) Snapshot(ctx context.Context) api.RouteSnapshot {
	candidates := make([]api.UpstreamSnapshot, 0, len(s.upstreams))
	for _, u := range s.upstreams {
		candidates = append(candidates, api.UpstreamSnapshot{
			ID:     u.ID(),
			Kind:   u.Kind(),
			Health: u.Health(ctx),
			Caps:   u.Caps(),
			Cost:   s.costs[u.ID()],
		})
	}
	return api.RouteSnapshot{
		TakenAt:    time.Now().UTC(),
		Candidates: candidates,
	}
}
