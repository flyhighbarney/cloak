// Package engine runs the DAG scheduler and wires stages → router → upstream
// → de-anonymized response. See docs/architecture.md.
package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"cloakline/internal/api"
	"cloakline/internal/audit"
	"cloakline/internal/obs/log"
	"cloakline/internal/obs/meter"
	"cloakline/internal/stage/dlptier1"
	"cloakline/internal/vault/session"
)

// Engine implements api.Engine.
type Engine struct {
	stages      []api.Stage
	levels      levels
	router      api.Router
	upstreams   map[api.UpstreamID]api.Upstream
	snapshotter *Snapshotter
	vault       *session.Vault
	logger      *log.Logger
	meter       api.Meter
	recorder    *audit.Recorder
}

// Config wires an Engine.
type Config struct {
	Stages      []api.Stage
	Router      api.Router
	Upstreams   []api.Upstream
	Snapshotter *Snapshotter
	Vault       *session.Vault
	Logger      *log.Logger
	Meter       api.Meter
	Recorder    *audit.Recorder
}

// New validates the DAG at boot and returns a ready engine.
func New(cfg Config) (*Engine, error) {
	ls, err := buildLevels(cfg.Stages)
	if err != nil {
		return nil, fmt.Errorf("DAG: %w", err)
	}
	ups := make(map[api.UpstreamID]api.Upstream, len(cfg.Upstreams))
	for _, u := range cfg.Upstreams {
		ups[u.ID()] = u
	}
	return &Engine{
		stages:      cfg.Stages,
		levels:      ls,
		router:      cfg.Router,
		upstreams:   ups,
		snapshotter: cfg.Snapshotter,
		vault:       cfg.Vault,
		logger:      cfg.Logger,
		meter:       cfg.Meter,
		recorder:    cfg.Recorder,
	}, nil
}

// Handle is the api.Engine entry point.
func (e *Engine) Handle(ctx context.Context, r *api.Request) (resp *api.Response, retErr error) {
	start := time.Now()
	bus := api.NewMapBus()
	var chosen api.UpstreamID
	var chosenModel string

	defer func() {
		if p := recover(); p != nil {
			retErr = fmt.Errorf("panic: %v", p)
			e.logger.ErrorCtx(ctx, "engine.panic", log.Fields{"panic": fmt.Sprintf("%v", p)})
			// Ensure the vault does not leak on panic. Close is idempotent.
			_ = e.vault.Close(ctx, r.Session, api.OutcomePanic)
		}
		e.meter.Histogram(meter.MetricRequestDurationSeconds, api.Dims{
			meter.DimMode:    r.Mode.String(),
			meter.DimOutcome: outcomeOf(retErr),
		}).Observe(time.Since(start).Seconds())

		if e.recorder != nil {
			e.recorder.Record(buildAuditEntry(ctx, r, bus, chosen, chosenModel, retErr, time.Since(start)))
		}
	}()

	if err := checkModes(e.levels, r.Mode); err != nil {
		return nil, err
	}

	// Assign identifiers before the vault opens — normalize does this too,
	// but the vault must be Open before any stage runs, so seed here.
	if r.ID == "" {
		r.ID = api.RequestID(newRandID(16))
	}
	if r.Session == "" {
		r.Session = api.SessionID(newRandID(16))
	}

	// Vault must be Open before DLP tokenizes.
	if err := e.vault.Begin(ctx, r.Session); err != nil {
		return nil, err
	}

	// Run DAG stages level-by-level, concurrently within a level.
	if err := e.runLevels(ctx, r, bus); err != nil {
		_ = e.vault.Close(ctx, r.Session, api.OutcomePolicyBlocked)
		return nil, err
	}

	// Snapshot + route.
	snap := e.snapshotter.Snapshot(ctx)
	decision, err := e.router.Select(ctx, r, snap)
	if err != nil {
		e.meter.Counter(meter.MetricRouteNoCandidateTotal, api.Dims{}).Inc()
		_ = e.vault.Close(ctx, r.Session, api.OutcomePolicyBlocked)
		return nil, err
	}
	e.meter.Counter(meter.MetricRouteDecisionsTotal, api.Dims{
		meter.DimUpstream: string(decision.Upstream),
	}).Inc()
	e.logger.InfoCtx(ctx, "route.decision", log.Fields{
		"upstream": string(decision.Upstream),
		"reason":   decision.Reason,
	})

	up, ok := e.upstreams[decision.Upstream]
	if !ok {
		_ = e.vault.Close(ctx, r.Session, api.OutcomeUpstreamError)
		return nil, fmt.Errorf("%w: upstream %s not registered",
			api.ErrCapMismatch, decision.Upstream)
	}
	chosen = up.ID()
	if ext, ok := r.Extensions.OpenAI(); ok && ext.Model != "" {
		chosenModel = ext.Model
	} else if ext, ok := r.Extensions.Anthropic(); ok && ext.Model != "" {
		chosenModel = ext.Model
	}

	// Transition vault for the response path.
	if r.Mode == api.ModeStreaming {
		if err := e.vault.Transition(ctx, r.Session, api.VaultStreaming); err != nil {
			_ = e.vault.Close(ctx, r.Session, api.OutcomeStreamAborted)
			return nil, err
		}
	} else {
		if err := e.vault.Transition(ctx, r.Session, api.VaultStreaming); err != nil {
			_ = e.vault.Close(ctx, r.Session, api.OutcomeUpstreamError)
			return nil, err
		}
	}

	upstreamStart := time.Now()
	rawResp, err := up.Send(ctx, r)
	e.meter.Histogram(meter.MetricUpstreamDurationSecs, api.Dims{
		meter.DimUpstream: string(up.ID()),
		meter.DimOutcome:  outcomeOf(err),
	}).Observe(time.Since(upstreamStart).Seconds())
	if err != nil {
		_ = e.vault.Close(ctx, r.Session, api.OutcomeUpstreamError)
		return nil, err
	}

	// De-anonymize on the return path.
	if r.Mode == api.ModeStreaming {
		return e.wrapStream(ctx, r, rawResp), nil
	}
	restored, err := e.deAnonymizeUnary(ctx, r.Session, rawResp)
	if err != nil {
		_ = e.vault.Close(ctx, r.Session, api.OutcomeUpstreamError)
		return nil, err
	}
	_ = e.vault.Transition(ctx, r.Session, api.VaultDraining)
	_ = e.vault.Close(ctx, r.Session, api.OutcomeSuccess)
	return restored, nil
}

func (e *Engine) runLevels(ctx context.Context, r *api.Request, bus api.SignalBus) error {
	for _, lvl := range e.levels {
		if err := e.runLevel(ctx, r, bus, lvl); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) runLevel(ctx context.Context, r *api.Request, bus api.SignalBus, lvl []api.Stage) error {
	if len(lvl) == 1 {
		return e.runOne(ctx, r, bus, lvl[0])
	}
	var wg sync.WaitGroup
	errCh := make(chan error, len(lvl))
	subctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for _, s := range lvl {
		wg.Add(1)
		go func(st api.Stage) {
			defer wg.Done()
			if err := e.runOne(subctx, r, bus, st); err != nil {
				errCh <- err
				cancel()
			}
		}(s)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) runOne(ctx context.Context, r *api.Request, bus api.SignalBus, s api.Stage) error {
	start := time.Now()
	err := s.Run(ctx, r, bus)
	e.meter.Histogram(meter.MetricStageDurationSeconds, api.Dims{
		meter.DimStage:   string(s.ID()),
		meter.DimOutcome: outcomeOf(err),
	}).Observe(time.Since(start).Seconds())
	if err != nil {
		e.meter.Counter(meter.MetricStageErrorsTotal, api.Dims{
			meter.DimStage: string(s.ID()),
		}).Inc()
	}
	return err
}

func (e *Engine) deAnonymizeUnary(ctx context.Context, sid api.SessionID, resp *api.Response) (*api.Response, error) {
	if resp.Full == nil {
		return resp, nil
	}
	for i, p := range resp.Full.Parts {
		if p.Modality != api.ModText {
			continue
		}
		restored, err := dlptier1.DeAnonymize(ctx, e.vault, sid, string(p.Bytes))
		if err != nil {
			return nil, err
		}
		resp.Full.Parts[i].Bytes = []byte(restored)
	}
	return resp, nil
}

func (e *Engine) wrapStream(ctx context.Context, r *api.Request, raw *api.Response) *api.Response {
	out := make(chan api.Chunk, 32)
	go func() {
		defer close(out)
		defer func() {
			_ = e.vault.Transition(ctx, r.Session, api.VaultDraining)
			_ = e.vault.Close(ctx, r.Session, api.OutcomeSuccess)
		}()
		for chunk := range raw.Chunks {
			if chunk.Err != nil {
				_ = e.vault.Transition(ctx, r.Session, api.VaultFailed)
				out <- chunk
				return
			}
			if chunk.Delta.Modality == api.ModText {
				restored, err := dlptier1.DeAnonymize(ctx, e.vault, r.Session, string(chunk.Delta.Bytes))
				if err != nil {
					_ = e.vault.Transition(ctx, r.Session, api.VaultFailed)
					out <- api.Chunk{Seq: chunk.Seq, Err: err}
					return
				}
				chunk.Delta.Bytes = []byte(restored)
			}
			select {
			case out <- chunk:
			case <-ctx.Done():
				_ = e.vault.Transition(ctx, r.Session, api.VaultFailed)
				select {
				case out <- api.Chunk{Err: ctx.Err()}:
				default:
				}
				return
			}
		}
	}()
	return &api.Response{
		APIVersion: raw.APIVersion,
		RequestID:  raw.RequestID,
		Mode:       api.ModeStreaming,
		Chunks:     out,
		Provider:   raw.Provider,
	}
}

func outcomeOf(err error) string {
	if err == nil {
		return "success"
	}
	switch {
	case errors.Is(err, api.ErrClientAbort):
		return "client_error"
	case errors.Is(err, api.ErrPolicyBlocked), errors.Is(err, api.ErrDLPRedaction):
		return "policy_blocked"
	case errors.Is(err, api.ErrRateLimit), errors.Is(err, api.ErrUnavailable), errors.Is(err, api.ErrProvider):
		return "upstream_error"
	}
	return "unknown"
}
