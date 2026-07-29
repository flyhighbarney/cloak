// Package extracttext is the DAG stage that flattens the text content of a
// request into a signal for downstream DLP/guard stages.
//
// For Phase 1 (text-only), this is a light pass: it counts characters and
// verifies each Message.Part is a supported modality. Fan-out for multimodal
// content lands with T-PDF/T-DLP-VISION.
package extracttext

import (
	"context"
	"fmt"

	"cloakline/internal/api"
	"cloakline/internal/stage/normalize"
)

const (
	ID = api.StageID("extract.text")

	SignalTextCharCount api.SignalName = "extract.text.char_count"
	SignalTextParts     api.SignalName = "extract.text.parts" // []int indices into Messages -> Parts
)

type Stage struct{}

func New() *Stage { return &Stage{} }

func (s *Stage) APIVersion() string         { return api.StageAPIVersion }
func (s *Stage) ID() api.StageID            { return ID }
func (s *Stage) Requires() []api.StageID    { return []api.StageID{normalize.ID} }
func (s *Stage) Produces() []api.SignalName {
	return []api.SignalName{SignalTextCharCount, SignalTextParts}
}
func (s *Stage) Modes() api.ModeSet { return api.ModesOf(api.ModeUnary, api.ModeStreaming) }

// TextPartRef identifies a specific text content atom within the request.
type TextPartRef struct {
	MessageIdx int
	PartIdx    int
}

func (s *Stage) Run(ctx context.Context, r *api.Request, bus api.SignalBus) error {
	total := 0
	var refs []TextPartRef
	for mi, m := range r.Messages {
		for pi, p := range m.Parts {
			switch p.Modality {
			case api.ModText:
				total += len(p.Bytes) // UTF-8 byte length approximates char cost
				refs = append(refs, TextPartRef{MessageIdx: mi, PartIdx: pi})
			case api.ModImage, api.ModAudio, api.ModVideo, api.ModPDF, api.ModArchive, api.ModOffice:
				// Deferred in Phase 1.
				return fmt.Errorf("%w: modality %s not supported in Phase 1",
					api.ErrConfigInvalid, p.Modality)
			default:
				return fmt.Errorf("%w: unknown modality on part[%d][%d]",
					api.ErrConfigInvalid, mi, pi)
			}
		}
	}
	if err := bus.Set(SignalTextCharCount, total); err != nil {
		return err
	}
	return bus.Set(SignalTextParts, refs)
}
