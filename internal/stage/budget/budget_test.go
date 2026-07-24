package budget

import (
	"context"
	"errors"
	"testing"

	"policyd/internal/api"
)

func TestBudgetAllowsUpToCap(t *testing.T) {
	store := NewStore(map[api.BudgetRef]Limits{
		"tenant-a": {DailyRequests: 3},
	})
	s := New(store)
	req := &api.Request{
		Mode:      api.ModeUnary,
		Messages:  []api.Message{{Role: api.RoleUser}},
		Principal: api.Principal{BudgetRef: "tenant-a"},
	}
	for i := 0; i < 3; i++ {
		bus := api.NewMapBus()
		if err := s.Run(context.Background(), req, bus); err != nil {
			t.Errorf("call %d: unexpected err: %v", i+1, err)
		}
	}
}

func TestBudgetBlocksBeyondCap(t *testing.T) {
	store := NewStore(map[api.BudgetRef]Limits{
		"tenant-a": {DailyRequests: 2},
	})
	s := New(store)
	req := &api.Request{
		Mode:      api.ModeUnary,
		Messages:  []api.Message{{Role: api.RoleUser}},
		Principal: api.Principal{BudgetRef: "tenant-a"},
	}
	_ = s.Run(context.Background(), req, api.NewMapBus())
	_ = s.Run(context.Background(), req, api.NewMapBus())
	err := s.Run(context.Background(), req, api.NewMapBus())
	if err == nil {
		t.Fatal("third call should fail")
	}
	if !errors.Is(err, api.ErrBudgetExceeded) {
		t.Errorf("want ErrBudgetExceeded, got %v", err)
	}
}

func TestBudgetUnlimitedForNoRef(t *testing.T) {
	store := NewStore(nil)
	s := New(store)
	req := &api.Request{
		Mode:      api.ModeUnary,
		Messages:  []api.Message{{Role: api.RoleUser}},
		Principal: api.Principal{BudgetRef: ""},
	}
	for i := 0; i < 100; i++ {
		if err := s.Run(context.Background(), req, api.NewMapBus()); err != nil {
			t.Errorf("call %d: unexpected err: %v", i, err)
		}
	}
}

func TestSnapshotReflectsConsumption(t *testing.T) {
	store := NewStore(map[api.BudgetRef]Limits{
		"tenant-a": {DailyRequests: 10},
	})
	_ = store.consume("tenant-a")
	_ = store.consume("tenant-a")
	view := store.Snapshot()
	got := view.Remaining["tenant-a"]
	if got != 8 {
		t.Errorf("want 8 remaining, got %v", got)
	}
}
