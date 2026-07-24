// Package normalize is the first DAG stage: validates the incoming Request
// and ensures required identifiers are set.
package normalize

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"policyd/internal/api"
)

const (
	ID = api.StageID("normalize")

	SignalRequestID api.SignalName = "normalize.request_id"
)

type Stage struct{}

func New() *Stage { return &Stage{} }

func (s *Stage) APIVersion() string          { return api.StageAPIVersion }
func (s *Stage) ID() api.StageID             { return ID }
func (s *Stage) Requires() []api.StageID     { return nil }
func (s *Stage) Produces() []api.SignalName  { return []api.SignalName{SignalRequestID} }
func (s *Stage) Modes() api.ModeSet          { return api.ModesOf(api.ModeUnary, api.ModeStreaming) }

func (s *Stage) Run(ctx context.Context, r *api.Request, bus api.SignalBus) error {
	if r.APIVersion == "" {
		r.APIVersion = "v1.0"
	}
	if r.ID == "" {
		r.ID = api.RequestID(randID(16))
	}
	if r.Session == "" {
		r.Session = api.SessionID(randID(16))
	}
	if r.Mode != api.ModeUnary && r.Mode != api.ModeStreaming {
		return fmt.Errorf("%w: request mode not set", api.ErrConfigInvalid)
	}
	if len(r.Messages) == 0 {
		return fmt.Errorf("%w: no messages", api.ErrConfigInvalid)
	}
	return bus.Set(SignalRequestID, r.ID)
}

func randID(n int) string {
	b := make([]byte, n/2)
	if _, err := rand.Read(b); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(b)
}
