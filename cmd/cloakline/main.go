// Command cloakline is the composition root. It wires stages, router,
// upstreams, vault, transport, and the engine, enforces version invariants,
// and runs the process until SIGTERM/SIGINT.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"path/filepath"
	"runtime"

	"cloakline/internal/adminui"
	"cloakline/internal/api"
	"cloakline/internal/audit"
	"cloakline/internal/backup"
	"cloakline/internal/config"
	"cloakline/internal/engine"
	"cloakline/internal/httpclient"
	"cloakline/internal/keyvault"
	"cloakline/internal/notify"
	"cloakline/internal/obs/log"
	"cloakline/internal/obs/meter"
	policycel "cloakline/internal/policy/cel"
	"cloakline/internal/prefs"
	routercel "cloakline/internal/router/cel"
	"cloakline/internal/stage/budget"
	"cloakline/internal/stage/dlptier1"
	"cloakline/internal/stage/extracttext"
	"cloakline/internal/stage/injection"
	"cloakline/internal/stage/normalize"
	"cloakline/internal/stage/reassemble"
	"cloakline/internal/tlsinspect"
	httpxport "cloakline/internal/transport/http"
	anthropicup "cloakline/internal/upstream/anthropic"
	openaiup "cloakline/internal/upstream/openai"
	"cloakline/internal/vault/session"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "update" {
		if err := runUpdate(); err != nil {
			fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

// runUpdate self-updates cloakline via npm.
func runUpdate() error {
	fmt.Println("Updating cloakline to the latest version...")
	cmd := exec.Command("npm", "install", "-g", "cloakline@latest")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("npm install failed: %w\n\nTo update manually, run: npm install -g cloakline@latest", err)
	}
	fmt.Println("cloakline updated successfully.")
	return nil
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
	logger, logPath, closeLog := newLogger(lvl)
	defer closeLog()

	// Stamp the build identity onto EVERY log line. This is deliberately a
	// base field, not just a one-off startup line: logs rotate and users
	// paste tails, so a startup-only banner is often missing from what we
	// actually get handed. With it on every record, any pasted line answers
	// "which build is this?" — the exact question that stalled diagnosis
	// before this existed.
	bi := resolveBuildInfo()
	logger = logger.With(bi.logFields())
	logger.Info("cloakline.build", log.Fields{
		"version":    bi.Version,
		"commit":     bi.Commit,
		"build_time": bi.BuildTime,
		"dirty":      bi.Dirty,
		"go":         runtime.Version(),
		"os_arch":    runtime.GOOS + "/" + runtime.GOARCH,
	})
	// Tell the operator where the log file lives, on stderr, so it's findable
	// even when stdout is swallowed by a scheduled task / service wrapper.
	if logPath != "" {
		fmt.Fprintf(os.Stderr, "cloakline %s — logging to %s\n", bi.String(), logPath)
	}

	// Install the OS-native keyring backend for dashboard-managed API
	// keys. On platforms without native support this is a no-op and
	// the in-memory backend stays active — the daemon still boots.
	if name, err := keyvault.Install(); err != nil {
		logger.Warn("keyvault.install_failed", log.Fields{"backend": name, "error": err.Error()})
	} else {
		logger.Info("keyvault.installed", log.Fields{"backend": name})
	}

	// Load config.
	ir, err := config.Load(*configDir)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	logger.Info("config.loaded", log.Fields{
		"hash":       ir.Hash,
		"env":        string(ir.Env),
		"security":   string(ir.SecurityMode),
		"providers":  len(ir.Providers),
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

	// Upstreams. Providers whose API key isn't available at startup
	// are silently skipped (warn-logged), not fatal. This lets
	// providers.yaml ship every reasonable default uncommented — the
	// running machine registers only the ones it can actually use.
	// See docs/session-notes.md finding #7.
	var upstreams []api.Upstream
	costs := make(map[api.UpstreamID]api.CostView)
	for _, p := range ir.Providers {
		key, err := config.APIKeyForProvider(p)
		if err != nil {
			logger.Warn("provider.skipped", log.Fields{
				"id":     string(p.ID),
				"kind":   string(p.Kind),
				"reason": "no api key available (env var unset and no vault entry)",
			})
			continue
		}
		switch p.Kind {
		case api.KindOpenAI:
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
			logger.Warn("provider.skipped", log.Fields{
				"id":     string(p.ID),
				"kind":   string(p.Kind),
				"reason": "kind not supported yet",
			})
			continue
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
		// Not fatal in tlsinspect mode: the transparent-inspection path
		// forwards to the real upstream host directly and uses the
		// CLI's own auth headers — the providers.yaml catalog is not
		// consulted. If the user later enables gateway mode (:4000
		// routing to a configured provider) they'll need to uncomment
		// an entry in providers.yaml, but until then, boot cleanly.
		logger.Warn("upstreams.none_configured", log.Fields{
			"note": "gateway routing at :4000 will 502; tlsinspect at :443/:8443 still works",
		})
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
	// Open the AES-encrypted prefs store. Failure is non-fatal — the
	// dashboard shows a warning and DLP falls back to tier defaults.
	prefsStore, prefsErr := prefs.Open()
	if prefsErr != nil {
		logger.Warn("prefs.open_failed", log.Fields{"error": prefsErr.Error()})
		prefsStore = nil
	}
	adminHandler, err := adminui.New(recorder, bi.String(), prefsStore)
	if err != nil {
		return fmt.Errorf("adminui: %w", err)
	}
	// Notifier fires system balloon tips when HIGH-tier content is redacted.
	// Closed at process exit (currently a no-op on non-Windows).
	notifier := notify.New()
	defer notifier.Close()

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
		if err := startInspect(ctx, ir, dlpActions, prefsStore, logger, adminHandler, notifier); err != nil {
			return fmt.Errorf("tlsinspect: %w", err)
		}
	}

	logger.Info("cloakline.starting", log.Fields{
		"listen":       ir.Listen,
		"admin_listen": ir.AdminListen,
		"config_hash":  ir.Hash,
	})
	if err := transport.Serve(ctx, eng); err != nil {
		return fmt.Errorf("transport: %w", err)
	}
	logger.Info("cloakline.stopped", log.Fields{"uptime_sec": int(time.Since(ir.Loaded).Seconds())})
	return nil
}

// newLogger builds the process logger, writing to stdout and (best-effort)
// to a rotating file under the user's config dir so errors survive after
// the daemon is running headless/as a background process — the file is
// what a user hands to support (or pastes to Claude) when something breaks.
// Failure to open the file is non-fatal: the daemon still logs to stdout.
// The returned path is the log file (empty if only stdout is active) so the
// caller can point the operator at it.
func newLogger(lvl log.Level) (*log.Logger, string, func()) {
	path, err := log.DefaultLogFile()
	if err != nil {
		return log.New(lvl), "", func() {}
	}
	f, err := log.OpenFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not open log file %s: %v\n", path, err)
		return log.New(lvl), "", func() {}
	}
	return log.NewMulti(lvl, os.Stdout, f), path, func() { f.Close() }
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
//
// adminHandler and notifier are used to wire the "Allow session"
// notification flow:
//  1. When a HIGH-tier finding is redacted, a nonce is issued by
//     adminHandler.IssueNonce and embedded in an allow URL.
//  2. notifier.Notify fires a platform alert (Windows balloon tip)
//     with that URL as the "Allow session" action.
//  3. When the user clicks the button, their browser opens the allow URL.
//  4. adminHandler serves GET /admin/session/allow, consumes the nonce,
//     and calls handler.OptOutSession(sessionKey) to grant the opt-out.
func startInspect(
	ctx context.Context,
	ir *config.IR,
	actions dlptier1.ActionMap,
	prefsStore *prefs.Store,
	logger *log.Logger,
	adminHandler *adminui.Handler,
	notifier notify.Notifier,
) error {
	caDir := ir.Inspect.CADir
	if caDir == "" {
		home, err := os.UserConfigDir()
		if err != nil {
			return err
		}
		caDir = home + string(os.PathSeparator) + "cloakline" + string(os.PathSeparator) + "ca"
	}

	// Automatic state backup — runs unattended every boot, keeps the newest
	// few, and never blocks startup. The user never has to think about it;
	// if a vault/config/CA ever gets corrupted, a clean copy is on disk.
	autoBackup(logger)

	ca, err := tlsinspect.LoadOrCreate(caDir)
	if err != nil {
		return err
	}
	handlerCfg := tlsinspect.HandlerConfig{
		Logger:       logger,
		Meter:        noopInspectMeter{},
		MaxBodyBytes: ir.MaxBodyBytes,
		DLPActions:   inspectActionResolver{actions},
	}
	if prefsStore != nil {
		handlerCfg.Prefs = prefsStore
	}
	handler := tlsinspect.NewHandler(handlerCfg)

	// Wire session opt-out: adminHandler needs handler.OptOutSession so
	// it can grant permission when a nonce is redeemed.
	adminHandler.WireSessionOptOut(handler)

	// Wire the notify callback: issue a nonce, build the allow URL, fire
	// the platform notification. adminBase derives from AdminListen.
	adminBase := adminListenBase(ir.AdminListen)
	handler.SetNotifyFunc(func(kind, sessionKey string) {
		nonce := adminHandler.IssueNonce(sessionKey)
		allowURL := adminBase + "/admin/session/allow?nonce=" + nonce
		notifier.Notify(kind, allowURL)
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

// autoBackup snapshots cloakline's mutable state on startup and keeps the
// newest few copies. It is fully automatic and best-effort: any failure is
// logged and swallowed so a backup problem can never stop the daemon from
// booting. Sources cover everything expensive-or-annoying to lose — the
// encrypted state dir (vault + prefs + CA), the pipeline config, and a copy
// of the OS hosts file (so a botched panic-restore can be reconstructed).
func autoBackup(logger *log.Logger) {
	cfgHome, err := os.UserConfigDir()
	if err != nil {
		logger.Warn("backup.skipped", log.Fields{"reason": "no user config dir", "err": err.Error()})
		return
	}
	stateDir := filepath.Join(cfgHome, "cloakline")
	destDir := filepath.Join(stateDir, "backups")

	sources := []backup.Source{
		{Path: stateDir, Label: "state"},
		{Path: "configs/pipeline.yaml", Label: "config"},
		{Path: "configs/providers.yaml", Label: "config"},
		{Path: hostsFilePath(), Label: "hosts"},
	}

	path, err := backup.Auto(destDir, sources, 10)
	if err != nil {
		logger.Warn("backup.failed", log.Fields{"err": err.Error()})
		return
	}
	logger.Info("backup.written", log.Fields{"path": path, "keep": 10})
}

// hostsFilePath returns the OS hosts file location for the running platform.
func hostsFilePath() string {
	if runtime.GOOS == "windows" {
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		return filepath.Join(root, "System32", "drivers", "etc", "hosts")
	}
	return "/etc/hosts"
}

// adminListenBase turns ir.AdminListen (":4001" or "127.0.0.1:4001")
// into "http://127.0.0.1:4001" for embedding in allow URLs.
func adminListenBase(listen string) string {
	if listen == "" {
		return "http://127.0.0.1:4001"
	}
	if strings.HasPrefix(listen, ":") {
		return "http://127.0.0.1" + listen
	}
	// Already has a host component.
	return "http://" + listen
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
