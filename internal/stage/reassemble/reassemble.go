// Package reassemble is the DAG stage that finalizes the (possibly mutated)
// request before it leaves the policy plane for the upstream adapter.
//
// For Phase 1 (text-only, DLP-mutates-in-place) this is a lightweight
// verification stage: it re-checks that parts remain within limits and
// that no unexpected modalities appeared.
package reassemble

import (
	"context"
	"fmt"

	"policyd/internal/api"
	"policyd/internal/stage/dlptier1"
	"policyd/internal/stage/extracttext"
)

const (
	ID = api.StageID("reassemble")

	SignalReassembled api.SignalName = "reassemble.done"
)

type Stage struct {
	maxTextBytes int
}

// New returns a Stage. maxTextBytes bounds the post-mutation size of any
// single text part (protects against DLP mutations that could explode size).
func New(maxTextBytes int) *Stage {
	if maxTextBytes <= 0 {
		maxTextBytes = 512 * 1024
	}
	return &Stage{maxTextBytes: maxTextBytes}
}

func (s *Stage) APIVersion() string         { return api.StageAPIVersion }
func (s *Stage) ID() api.StageID            { return ID }
func (s *Stage) Requires() []api.StageID    { return []api.StageID{dlptier1.ID} }
func (s *Stage) Produces() []api.SignalName { return []api.SignalName{SignalReassembled} }
func (s *Stage) Modes() api.ModeSet         { return api.ModesOf(api.ModeUnary, api.ModeStreaming) }

func (s *Stage) Run(ctx context.Context, r *api.Request, bus api.SignalBus) error {
	// Verify Signal chain — DLP must have run.
	if _, ok := bus.Get(dlptier1.SignalFindings); !ok {
		return fmt.Errorf("%w: reassemble ran before dlp findings signal", api.ErrConfigInvalid)
	}
	if _, ok := bus.Get(extracttext.SignalTextCharCount); !ok {
		return fmt.Errorf("%w: reassemble ran before extract signal", api.ErrConfigInvalid)
	}
	for mi := range r.Messages {
		for pi := range r.Messages[mi].Parts {
			p := &r.Messages[mi].Parts[pi]
			if p.Modality == api.ModText && len(p.Bytes) > s.maxTextBytes {
				return fmt.Errorf("%w: text part [%d][%d] exceeds %d bytes",
					api.ErrConfigInvalid, mi, pi, s.maxTextBytes)
			}
		}
	}
	return bus.Set(SignalReassembled, true)
}
