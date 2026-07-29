package api

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// Stage is a DAG node in the policy engine.
// See docs/architecture.md for the DAG scheduler contract.
type Stage interface {
	APIVersion() string
	ID() StageID
	Requires() []StageID
	Produces() []SignalName
	Modes() ModeSet
	Run(ctx context.Context, r *Request, bus SignalBus) error
}

// SignalBus carries per-request annotations between stages.
// Values are opaque; readers must type-assert.
type SignalBus interface {
	Set(name SignalName, value any) error
	Get(name SignalName) (any, bool)
}

// MapBus is the default in-memory SignalBus implementation.
// Safe for concurrent use — the engine may call Set from parallel stages.
type MapBus struct {
	mu sync.RWMutex
	m  map[SignalName]any
}

func NewMapBus() *MapBus { return &MapBus{m: make(map[SignalName]any)} }

func (b *MapBus) Set(name SignalName, value any) error {
	if name == "" {
		return errors.New("SignalBus.Set: empty name")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, exists := b.m[name]; exists {
		return fmt.Errorf("SignalBus.Set: signal %q already produced", name)
	}
	b.m[name] = value
	return nil
}

func (b *MapBus) Get(name SignalName) (any, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	v, ok := b.m[name]
	return v, ok
}
