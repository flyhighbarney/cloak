package engine

import (
	"fmt"
	"sort"

	"cloakline/internal/api"
)

// levels is a topological grouping of stages such that all stages within
// one level are mutually independent (may run concurrently), and every
// stage in level N depends only on stages in levels 0..N-1.
type levels [][]api.Stage

// buildLevels computes a level-order execution plan from the stage set.
// Returns an error on cycles, duplicate IDs, or unresolved dependencies.
func buildLevels(stages []api.Stage) (levels, error) {
	byID := make(map[api.StageID]api.Stage, len(stages))
	for _, s := range stages {
		if _, exists := byID[s.ID()]; exists {
			return nil, fmt.Errorf("duplicate stage id %q", s.ID())
		}
		byID[s.ID()] = s
	}
	// Validate all Requires exist.
	for _, s := range stages {
		for _, req := range s.Requires() {
			if _, ok := byID[req]; !ok {
				return nil, fmt.Errorf("stage %q requires unknown stage %q", s.ID(), req)
			}
		}
	}
	// Kahn's algorithm with level grouping.
	inDeg := make(map[api.StageID]int, len(stages))
	for _, s := range stages {
		inDeg[s.ID()] = len(s.Requires())
	}
	var out levels
	remaining := len(stages)
	for remaining > 0 {
		var lvl []api.Stage
		var lvlIDs []api.StageID
		for _, s := range stages {
			if _, ok := byID[s.ID()]; !ok {
				continue
			}
			if inDeg[s.ID()] == 0 {
				lvl = append(lvl, s)
				lvlIDs = append(lvlIDs, s.ID())
			}
		}
		if len(lvl) == 0 {
			// Cycle.
			return nil, fmt.Errorf("stage cycle detected among %d remaining stages", remaining)
		}
		sort.Slice(lvl, func(i, j int) bool { return lvl[i].ID() < lvl[j].ID() })
		out = append(out, lvl)
		for _, id := range lvlIDs {
			delete(byID, id)
			// Decrement in-degree of successors.
			for _, s := range stages {
				for _, r := range s.Requires() {
					if r == id {
						inDeg[s.ID()]--
					}
				}
			}
		}
		remaining -= len(lvl)
	}
	return out, nil
}

// checkModes verifies every stage supports the request mode.
func checkModes(ls levels, mode api.Mode) error {
	for _, lvl := range ls {
		for _, s := range lvl {
			if !s.Modes().Has(mode) {
				return fmt.Errorf("stage %q does not support mode %s", s.ID(), mode)
			}
		}
	}
	return nil
}
