// Command policyd is the composition root. It wires stages, router,
// upstreams, vault, transport, and the engine, enforces version invariants,
// and runs the process until SIGTERM/SIGINT.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"policyd/internal/adminui"
	"policyd/internal/api"
	"policyd/internal/audit"
	"policyd/internal/config"
	"policyd/internal/engine"
	"policyd/internal/httpclient"
	"policyd/internal/obs/log"
	"policyd/internal/obs/meter"
	policycel "policyd/internal/policy/cel"
	routercel "policyd/internal/router/cel"
	"policyd/internal/stage/budget"
	"policyd/internal/stage/dlptier1"
	"policyd/internal/stage/extracttext"
	"policyd/internal/stage/injection"
	"policyd/internal/stage/normalize"
	"policyd/internal/stage/reassemble"
	"policyd/internal/tlsinspect"
	httpxport "policyd/internal/transport/http"
	anthropicup "policyd/internal/upstream/anthropic"
	openaiup "policyd/internal/upstream/openai"
	"policyd/internal/vault/session"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	configDir := flag.String("config", "./configs", "Path to config directory")
	healthcheck := flag.Bool("healthcheck", false, "Probe the local admin /healthz endpoint and exit 0 on success")
	flag.Parse()

	if *healthcheck {
		return runHealthcheck()
	}

	// Log level from env; defaults to info.
	lvl := parseLogLevel(os.Getenv("LOG_LEVEL"))
	logger := log.New(lvl)

	// Load config.
	ir, err := config.Load(*configDir)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	logger.Info("config.loaded", log.Fields{
		"hash":      ir.Hash,
		"env":       string(ir.Env),
		"security":  string(ir.SecurityMode),
		"providers": len(ir.Providers),
		"principals": len(ir.Principals),
	})

	// Governance invariant: refuse debug logging in prod (see threat-model.md G2).
	if ir.Env == config.EnvProd && lvl == log.LevelDebug {
		return fmt.Errorf("governance invariant: LOG_LEVEL=debug with env=prod is refused")
	}

	// Auth store.
	authStore, err := config.LoadIntoAuth(ir)
	if err != nil {
		return fmt.Errorf("auth: %w", err)
	}
	logger.Info("auth.loaded", log.Fields{"principals": authStore.Count()})

	// Meter.
	promReg := prometheus.NewRegistry()
	m := meter.New(promReg)

	// Emit config-hash gauge.
	m.Gauge(meter.MetricConfigLoadTimestampSecs, api.Dims{}).Set(float64(ir.Loaded.Unix()))

	// SSRF policy: allowlist all provider base-URL hosts; loopback only if any local.
	sspol := buildSSRFPolicy(ir)
	httpCli := httpclient.New(sspol)

	// Validate provider URLs against SSRF policy at boot.
	for _, p := range ir.Providers {
		if err := httpclient.ValidateURL(sspol, p.BaseURL); err != nil {
			return fmt.Errorf("provider %s base_url: %w", p.ID, err)
		}
	}

	// Upstreams. Only OpenAI supported in Phase 1.
	var upstreams []api.Upstream
	costs := make(map[api.UpstreamID]api.CostView)
	for _, p := range ir.Providers {
		switch p.Kind {
		case api.KindOpenAI:
			key, err := config.APIKeyForProvider(p)
			if err != nil {
				return err
			}
			ad := openaiup.New(openaiup.Config{
				ID:         p.ID,
				BaseURL:    p.BaseURL,
				APIKey:     key,
				Model:      p.Model,
				MaxContext: p.MaxContext,
				CostIn:     p.CostIn,
				CostOut:    p.CostOut,
			}, httpCli)
			upstreams = append(upstreams, ad)
		case api.KindAnthropic:
			key, err := config.APIKeyForProvider(p)
			if err != nil {
				return err
			}
			ad := anthropicup.New(anthropicup.Config{
				ID:         p.ID,
				BaseURL:    p.BaseURL,
				APIKey:     key,
				Model:      p.Model,
				MaxContext: p.MaxContext,
				CostIn:     p.CostIn,
				CostOut:    p.CostOut,
			}, httpCli)
			upstreams = append(upstreams, ad)
		default:
			return fmt.Errorf("provider %s: kind %q not supported yet", p.ID, p.Kind)
		}
		costs[p.ID] = api.CostView{
			CostPer1KIn:  p.CostIn,
			CostPer1KOut: p.CostOut,
		}
		logger.Info("upstream.registered", log.Fields{
			"id":   string(p.ID),
			"kind": string(p.Kind),
		})
	}
	if len(upstreams) == 0 {
		return fmt.Errorf("no upstreams configured")
	}

	// Vault.
	vault := session.New()

	// Audit recorder for /admin dashboard.
	recorder := audit.New(1000)

	// Policy engine.
	polEng, err := policycel.NewEngine()
	if err != nil {
		return fmt.Errorf("cel engine: %w", err)
	}
	var compiledPolicies []api.Policy
	for _, p := range ir.Policies {
		cp, err := polEng.Compile(p.Expression, p.Kind, p.ID)
		if err != nil {
			return fmt.Errorf("policy %s: %w", p.ID, err)
		}
		compiledPolicies = append(compiledPolicies, cp)
	}
	if len(compiledPolicies) == 0 {
		return fmt.Errorf("no routing policies compiled")
	}

	// Router.
	router := routercel.New(polEng, compiledPolicies)

	// Snapshotter.
	snap := engine.NewSnapshotter(upstreams, costs)

	// Stages.
	dlpActions := dlptier1.ActionMap{
		Default: ir.DLP.Default,
		ByKind:  ir.DLP.ByKind,
	}

	// Budget store — one shared instance across all requests.
	budgetLimits := make(map[api.BudgetRef]budget.Limits, len(ir.Budgets))
	for ref, b := range ir.Budgets {
		budgetLimits[ref] = budget.Limits{DailyRequests: b.DailyRequests}
	}
	budgetStore := budget.NewStore(budgetLimits)

	stages := []api.Stage{
		normalize.New(),
		budget.New(budgetStore), // pre-flight — cheap to enforce before scans
		extracttext.New(),
		// DLP and injection detection are independent — engine runs them
		// concurrently (they both only depend on extract.text).
		dlptier1.New(vault, dlpActions),
		injection.New(injection.Config{Threshold: ir.Injection.Threshold}),
		reassemble.New(512 * 1024),
	}

	// Admin dashboard.
	adminHandler, err := adminui.New(recorder, "v0.1.0")
	if err != nil {
		return fmt.Errorf("adminui: %w", err)
	}

	// Transport (constructed early so we can version-check).
	metricsHandler := promhttp.HandlerFor(promReg, promhttp.HandlerOpts{})
	transport := httpxport.New(httpxport.Config{
		Listen:             ir.Listen,
		AdminListen:        ir.AdminListen,
		MaxBodyBytes:       ir.MaxBodyBytes,
		RequestTimeout:     ir.RequestTimeout,
		Auth:               authStore,
		Logger:             logger,
		Meter:              m,
		MetricsHandler:     metricsHandler,
		AdminHandler:       adminHandler,
		RateLimitPerSecond: ir.RateLimit.PerSecond,
		RateLimitBurst:     ir.RateLimit.Burst,
	})

	// Version invariants — loud failure if anything is out of range.
	assertAll(stages, router, upstreams, transport, vault, m, polEng)

	// Engine.
	eng, err := engine.New(engine.Config{
		Stages:      stages,
		Router:      router,
		Upstreams:   upstreams,
		Snapshotter: snap,
		Vault:       vault,
		Logger:      logger,
		Meter:       m,
		Recorder:    recorder,
	})
	if err != nil {
		return fmt.Errorf("engine: %w", err)
	}

	// Ensure the meter has a hook to expose component versions.
	m.Gauge(meter.MetricComponentVersion, api.Dims{
		meter.DimComponent: "engine",
		meter.DimImpl:      "engine-v1",
		meter.DimVersion:   "v1.0",
	}).Set(1)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Optional: start the TLS inspection module as a background goroutine.
	if ir.Inspect.Enabled {
		if err := startInspect(ctx, ir, dlpActions, logger); err != nil {
			return fmt.Errorf("tlsinspect: %w", err)
		}
	}

	logger.Info("policyd.starting", log.Fields{
		"listen":       ir.Listen,
		"admin_listen": ir.AdminListen,
		"config_hash":  ir.Hash,
	})
	if err := transport.Serve(ctx, eng); err != nil {
		return fmt.Errorf("transport: %w", err)
	}
	logger.Info("policyd.stopped", log.Fields{"uptime_sec": int(time.Since(ir.Loaded).Seconds())})
	return nil
}

func parseLogLevel(s string) log.Level {
	switch strings.ToLower(s) {
	case "debug":
		return log.LevelDebug
	case "warn":
		return log.LevelWarn
	case "error":
		return log.LevelError
	}
	return log.LevelInfo
}

func buildSSRFPolicy(ir *config.IR) httpclient.Policy {
	hosts := make([]string, 0, len(ir.Providers))
	anyLocal := false
	schemes := map[string]struct{}{"https": {}}
	for _, p := range ir.Providers {
		if h := hostOf(p.BaseURL); h != "" {
			hosts = append(hosts, h)
		}
		if p.Local {
			anyLocal = true
			schemes["http"] = struct{}{}
		}
	}
	schList := make([]string, 0, len(schemes))
	for s := range schemes {
		schList = append(schList, s)
	}
	p := httpclient.StrictPolicy(hosts...)
	p.AllowSchemes = schList
	p.AllowLoopback = anyLocal
	return p
}

// startInspect boots the TLS inspection listener in a goroutine. Failure
// during boot returns immediately; runtime errors after boot are logged
// but do not kill the main gateway.
func startInspect(ctx context.Context, ir *config.IR, actions dlptier1.ActionMap, logger *log.Logger) error {
	caDir := ir.Inspect.CADir
	if caDir == "" {
		home, err := os.UserConfigDir()
		if err != nil {
			return err
		}
		caDir = home + string(os.PathSeparator) + "policyd" + string(os.PathSeparator) + "ca"
	}
	ca, err := tlsinspect.LoadOrCreate(caDir)
	if err != nil {
		return err
	}
	handler := tlsinspect.NewHandler(tlsinspect.HandlerConfig{
		Logger:             logger,
		Meter:              noopInspectMeter{},
		MaxBodyBytes:       ir.MaxBodyBytes,
		DLPActions:         inspectActionResolver{actions},
		InjectionThreshold: ir.Injection.Threshold,
	})
	srv, err := tlsinspect.NewServer(tlsinspect.Config{
		Listen: ir.Inspect.Listen,
		Hosts:  ir.Inspect.Hosts,
	}, ca, handler, logger)
	if err != nil {
		return err
	}
	go func() {
		if err := srv.Serve(ctx); err != nil {
			logger.Error("tlsinspect.exited", log.Fields{"err": err.Error()})
		}
	}()
	return nil
}

// noopInspectMeter satisfies tlsinspect.MeterFacade until we plug in the
// real Prometheus one.
type noopInspectMeter struct{}

func (noopInspectMeter) Counter(_ api.MetricName, _ map[api.DimKey]string) {}

// inspectActionResolver maps kind names to configured DLP actions.
type inspectActionResolver struct {
	m dlptier1.ActionMap
}

func (r inspectActionResolver) Action(kind string) string {
	return r.m.Action(api.PIIKind(kind)).String()
}

func hostOf(rawURL string) string {
	i := strings.Index(rawURL, "://")
	if i < 0 {
		return ""
	}
	rest := rawURL[i+3:]
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		rest = rest[:j]
	}
	if j := strings.Index(rest, ":"); j >= 0 {
		rest = rest[:j]
	}
	return rest
}
