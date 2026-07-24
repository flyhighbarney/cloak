// Package budget is a pre-flight budget enforcement stage.
//
// Every principal has a BudgetRef pointing at a per-tenant limit. This stage
// increments the counter and blocks with ErrBudgetExceeded when the cap
// is reached. The transport maps that to HTTP 429.
//
// State is in-memory. Counters reset at UTC midnight. When persistence
// lands (tripwire T-PERSIST), the Store interface here is the seam.
package budget

import (
	"context"
	"fmt"
	"sync"
	"time"

	"cloakline/internal/api"
	"cloakline/internal/stage/normalize"
)

const (
	ID = api.StageID("budget.enforce")

	SignalRemaining api.SignalName = "budget.remaining"
)

// Limits define what a BudgetRef permits per UTC day.
// Zero means unlimited on that axis.
type Limits struct {
	DailyRequests int
}

// Store tracks counters per BudgetRef. Safe for concurrent use.
type Store struct {
	mu       sync.Mutex
	current  map[api.BudgetRef]int
	limits   map[api.BudgetRef]Limits
	dayStamp string // yyyy-mm-dd UTC — used to detect midnight rollover
}

// NewStore returns an empty store with the given per-ref limits.
func NewStore(limits map[api.BudgetRef]Limits) *Store {
	return &Store{
		current:  make(map[api.BudgetRef]int),
		limits:   limits,
		dayStamp: time.Now().UTC().Format("2006-01-02"),
	}
}

// Snapshot returns a read-only projection of remaining capacity. Used by
// the snapshotter to feed the router.
func (s *Store) Snapshot() api.BudgetView {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rolloverIfNeeded()
	rem := make(map[api.BudgetRef]float64, len(s.limits))
	for ref, lim := range s.limits {
		if lim.DailyRequests <= 0 {
			rem[ref] = -1 // unlimited
			continue
		}
		used := s.current[ref]
		remaining := lim.DailyRequests - used
		if remaining < 0 {
			remaining = 0
		}
		rem[ref] = float64(remaining)
	}
	return api.BudgetView{Remaining: rem}
}

// consume increments the counter and enforces the cap. Returns
// ErrBudgetExceeded when the request would push the counter over.
func (s *Store) consume(ref api.BudgetRef) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rolloverIfNeeded()
	if ref == "" {
		return nil // no budget → unlimited
	}
	lim, ok := s.limits[ref]
	if !ok || lim.DailyRequests <= 0 {
		s.current[ref]++
		return nil
	}
	if s.current[ref] >= lim.DailyRequests {
		return fmt.Errorf("%w: %s exhausted for today", api.ErrBudgetExceeded, ref)
	}
	s.current[ref]++
	return nil
}

// rolloverIfNeeded resets counters when the UTC day changes.
// Caller must hold s.mu.
func (s *Store) rolloverIfNeeded() {
	today := time.Now().UTC().Format("2006-01-02")
	if today != s.dayStamp {
		s.current = make(map[api.BudgetRef]int, len(s.current))
		s.dayStamp = today
	}
}

// -------- Stage --------

// Stage enforces budgets pre-flight (before any upstream call).
type Stage struct {
	store *Store
}

func New(store *Store) *Stage { return &Stage{store: store} }

func (s *Stage) APIVersion() string         { return api.StageAPIVersion }
func (s *Stage) ID() api.StageID            { return ID }
func (s *Stage) Requires() []api.StageID    { return []api.StageID{normalize.ID} }
func (s *Stage) Produces() []api.SignalName { return []api.SignalName{SignalRemaining} }
func (s *Stage) Modes() api.ModeSet         { return api.ModesOf(api.ModeUnary, api.ModeStreaming) }

func (s *Stage) Run(ctx context.Context, r *api.Request, bus api.SignalBus) error {
	if err := s.store.consume(r.Principal.BudgetRef); err != nil {
		return err
	}
	// Attach snapshot for the router / admin surfaces.
	return bus.Set(SignalRemaining, s.store.Snapshot().Remaining)
}
