// Package adminui serves the read-only /admin dashboard and the
// small POST surface for managing dashboard-stored API keys.
//
// Server-rendered HTML, no JavaScript framework, no build step.
// Two embedded templates: dashboard.html (main page) and keys.html
// (partial rendered under /admin/keys).
package adminui

import (
	"context"
	"crypto/rand"
	"embed"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"cloakline/internal/audit"
	"cloakline/internal/keyvault"
	"cloakline/internal/obs/log"
	"cloakline/internal/prefs"
)

// SessionOptOut is satisfied by tlsinspect.Handler. The admin handler
// calls it when a user redeems an allow-session nonce.
type SessionOptOut interface {
	OptOutSession(sessionKey string)
}

// ConnectivityProber is satisfied by tlsinspect.Handler. The admin handler
// calls it from /admin/api/connectivity to verify the upstream is reachable.
type ConnectivityProber interface {
	ProbeConnectivity(ctx context.Context) (latencyMS int64, err error)
}

//go:embed templates/*.html
var templatesFS embed.FS

const (
	csrfCookieName = "cloakline_csrf"
	csrfFormField  = "csrf"
)

// nonceEntry is one pending "allow this session" nonce.
type nonceEntry struct {
	sessionKey string
	issued     time.Time
}

const nonceTTL = 5 * time.Minute

// Handler serves /admin, /admin/, /admin/keys, /admin/keys/delete,
// /admin/prefs, /admin/session/allow. It's a plain http.Handler; the
// transport plugs it into the admin listener (defaults to 127.0.0.1:4001).
type Handler struct {
	recorder          *audit.Recorder
	tmpl              *template.Template
	version           string
	prefs             *prefs.Store
	sessionOptOut     SessionOptOut     // optional; nil = allow-session noop
	connectivityProbe ConnectivityProber // optional; nil disables /connectivity

	nonceMu sync.Mutex
	nonces  map[string]nonceEntry // hex nonce → entry
}

// Option is a functional option for New.
type Option func(*Handler)

// WithSessionOptOut wires the handler that grants sessions
// allow-through permission. Called when a user redeems the nonce from
// the notification balloon by opening the allow URL in their browser.
func WithSessionOptOut(s SessionOptOut) Option {
	return func(h *Handler) { h.sessionOptOut = s }
}

// New constructs the admin handler. The prefs store is optional —
// if nil, the /admin/prefs page shows a warning that persistence is
// unavailable.
func New(recorder *audit.Recorder, version string, prefsStore *prefs.Store, opts ...Option) (*Handler, error) {
	tmpl, err := template.New("admin").Funcs(funcs()).ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	h := &Handler{
		recorder: recorder,
		tmpl:     tmpl,
		version:  version,
		prefs:    prefsStore,
		nonces:   make(map[string]nonceEntry),
	}
	for _, o := range opts {
		o(h)
	}
	return h, nil
}

// WireSessionOptOut sets the opt-out handler after construction. Called
// by main.go once both adminui.Handler and tlsinspect.Handler exist.
// Not safe to call concurrently with ServeHTTP.
func (h *Handler) WireSessionOptOut(s SessionOptOut) {
	h.sessionOptOut = s
}

// WireConnectivityProber sets the connectivity probe after construction.
// Not safe to call concurrently with ServeHTTP.
func (h *Handler) WireConnectivityProber(p ConnectivityProber) {
	h.connectivityProbe = p
}

// IssueNonce generates a single-use 5-minute token tied to sessionKey.
// The caller embeds it in the allow URL shown in the system notification.
// Expired nonces are evicted lazily on each call.
func (h *Handler) IssueNonce(sessionKey string) string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	nonce := hex.EncodeToString(buf)

	h.nonceMu.Lock()
	defer h.nonceMu.Unlock()
	// Lazy eviction of stale entries.
	now := time.Now()
	for k, e := range h.nonces {
		if now.Sub(e.issued) > nonceTTL {
			delete(h.nonces, k)
		}
	}
	h.nonces[nonce] = nonceEntry{sessionKey: sessionKey, issued: now}
	return nonce
}

// ServeHTTP dispatches based on method + trimmed path suffix.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Ensure a CSRF cookie exists on every response — cheap, one-time
	// per browser session, no server-side store.
	token := h.ensureCSRF(w, r)

	sub := strings.TrimPrefix(r.URL.Path, "/admin")
	sub = strings.TrimPrefix(sub, "/")

	switch {
	case r.Method == http.MethodGet && (sub == "" || sub == "index"):
		h.renderDashboard(w, r, token)
	case r.Method == http.MethodGet && sub == "keys":
		h.renderKeys(w, r, token, "")
	case r.Method == http.MethodPost && sub == "keys":
		h.postKeySet(w, r, token)
	case r.Method == http.MethodPost && sub == "keys/delete":
		h.postKeyDelete(w, r, token)
	case r.Method == http.MethodGet && sub == "prefs":
		h.renderPrefs(w, r, token, "")
	case r.Method == http.MethodPost && sub == "prefs":
		h.postPrefs(w, r, token)
	case r.Method == http.MethodGet && sub == "logs":
		h.renderLogs(w, r)
	case r.Method == http.MethodGet && sub == "api/logs":
		h.getAPILogs(w, r)
	case r.Method == http.MethodGet && sub == "session/allow":
		h.getSessionAllow(w, r)
	case r.Method == http.MethodGet && sub == "api/status":
		h.getAPIStatus(w, r)
	case r.Method == http.MethodGet && sub == "api/recent":
		h.getAPIRecent(w, r)
	case r.Method == http.MethodGet && sub == "api/connectivity":
		h.getAPIConnectivity(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) writeSecurityHeaders(w http.ResponseWriter, allowForms bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	formAction := "'none'"
	if allowForms {
		formAction = "'self'"
	}
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action "+formAction)
}

func (h *Handler) renderDashboard(w http.ResponseWriter, r *http.Request, token string) {
	limit := 100
	if s := r.URL.Query().Get("n"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	entries := h.recorder.Recent(limit)
	stats := h.recorder.Stats()

	data := struct {
		Now              string
		Version          string
		Stats            audit.Stats
		TimeSaved        string
		Entries          []audit.Entry
		Limit            int
		CSRFToken        string
		VaultBackend     string
	}{
		Now:          time.Now().UTC().Format(time.RFC3339),
		Version:      h.version,
		Stats:        stats,
		TimeSaved:    humanizeDuration(stats.EstimatedTimeSaved()),
		Entries:      entries,
		Limit:        limit,
		CSRFToken:    token,
		VaultBackend: keyvault.ActiveBackendName(),
	}

	h.writeSecurityHeaders(w, false)
	if err := h.tmpl.ExecuteTemplate(w, "dashboard.html", data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

type keyRow struct {
	Provider string
	Masked   string
}

func (h *Handler) renderKeys(w http.ResponseWriter, _ *http.Request, token, flash string) {
	providers, _ := keyvault.List()
	rows := make([]keyRow, 0, len(providers))
	for _, p := range providers {
		v, err := keyvault.Get(p)
		masked := "(unreadable)"
		if err == nil {
			masked = keyvault.Mask(v)
		}
		rows = append(rows, keyRow{Provider: p, Masked: masked})
	}
	data := struct {
		Now          string
		Version      string
		Rows         []keyRow
		CSRFToken    string
		Flash        string
		VaultBackend string
	}{
		Now:          time.Now().UTC().Format(time.RFC3339),
		Version:      h.version,
		Rows:         rows,
		CSRFToken:    token,
		Flash:        flash,
		VaultBackend: keyvault.ActiveBackendName(),
	}
	h.writeSecurityHeaders(w, true)
	if err := h.tmpl.ExecuteTemplate(w, "keys.html", data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func (h *Handler) postKeySet(w http.ResponseWriter, r *http.Request, token string) {
	if !h.checkCSRF(r, token) {
		http.Error(w, "csrf failed", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	provider := r.PostFormValue("provider")
	key := r.PostFormValue("key")
	if err := keyvault.Set(provider, key); err != nil {
		h.renderKeys(w, r, token, "Could not save: "+err.Error())
		return
	}
	// PRG: redirect after successful POST so refresh doesn't resubmit.
	http.Redirect(w, r, "/admin/keys", http.StatusSeeOther)
}

func (h *Handler) postKeyDelete(w http.ResponseWriter, r *http.Request, token string) {
	if !h.checkCSRF(r, token) {
		http.Error(w, "csrf failed", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	provider := r.PostFormValue("provider")
	if err := keyvault.Delete(provider); err != nil && !errors.Is(err, keyvault.ErrNotFound) {
		h.renderKeys(w, r, token, "Could not delete: "+err.Error())
		return
	}
	http.Redirect(w, r, "/admin/keys", http.StatusSeeOther)
}

// ensureCSRF sets a random 32-hex-char cookie if none is present, and
// returns whichever token the browser now holds. Double-submit pattern:
// POST handlers compare the form field to the cookie value.
func (h *Handler) ensureCSRF(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(csrfCookieName); err == nil && len(c.Value) == 32 {
		return c.Value
	}
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	tok := hex.EncodeToString(buf)
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    tok,
		Path:     "/admin",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	return tok
}

func (h *Handler) checkCSRF(r *http.Request, current string) bool {
	c, err := r.Cookie(csrfCookieName)
	if err != nil || c.Value == "" {
		return false
	}
	if err := r.ParseForm(); err != nil {
		return false
	}
	got := r.PostFormValue(csrfFormField)
	// Constant-time equality is overkill here (both are random 32-char
	// hex values with no timing-oracle upside), but cheap.
	return got != "" && got == c.Value && c.Value == current
}

// prefsRow is one row on the /admin/prefs toggle grid.
type prefsRow struct {
	Kind        string
	Tier        string
	Default     string // e.g. "redact", "allow"
	Current     string // "" == follow default
	Description string
}

var prefsRows = []prefsRow{
	{Kind: "api_key", Tier: "high", Default: "redact_one_way", Description: "Generic API keys (sk-*, pk-*, token_*, secret_*)"},
	{Kind: "aws_key", Tier: "high", Default: "redact_one_way", Description: "AWS access key IDs (AKIA...)"},
	{Kind: "github_token", Tier: "high", Default: "redact_one_way", Description: "GitHub tokens (ghp_, ghs_, github_pat_, ...)"},
	{Kind: "private_key", Tier: "high", Default: "redact_one_way", Description: "-----BEGIN ... PRIVATE KEY----- blocks"},
	{Kind: "password", Tier: "high", Default: "redact_one_way", Description: "Labelled password blocks (asks for y/n on intentional pastes)"},
	{Kind: "credit_card", Tier: "high", Default: "redact_one_way", Description: "Luhn-valid card numbers (asks for y/n on intentional pastes)"},
	{Kind: "ssn", Tier: "medium", Default: "redact", Description: "US SSN xxx-xx-xxxx (tokenized round-trip)"},
	{Kind: "email", Tier: "low", Default: "allow", Description: "Email addresses (flagged on dashboard; body never modified)"},
	{Kind: "phone", Tier: "low", Default: "allow", Description: "Phone numbers (flagged on dashboard; body never modified)"},
	{Kind: "ip_address", Tier: "low", Default: "allow", Description: "IPv4 dotted quads (flagged, not modified)"},
	{Kind: "url_path", Tier: "low", Default: "allow", Description: "HTTPS URLs with a path (flagged, not modified)"},
}

func (h *Handler) renderPrefs(w http.ResponseWriter, _ *http.Request, token, flash string) {
	var current prefs.Prefs
	if h.prefs != nil {
		if p, err := h.prefs.Load(); err == nil {
			current = p
		}
	}
	rows := make([]prefsRow, 0, len(prefsRows))
	for _, r := range prefsRows {
		row := r
		if v, ok := current.Kinds[r.Kind]; ok {
			row.Current = v.Action
		}
		rows = append(rows, row)
	}
	data := struct {
		Now       string
		Version   string
		Rows      []prefsRow
		CSRFToken string
		Flash     string
		Available bool
	}{
		Now:       time.Now().UTC().Format(time.RFC3339),
		Version:   h.version,
		Rows:      rows,
		CSRFToken: token,
		Flash:     flash,
		Available: h.prefs != nil,
	}
	h.writeSecurityHeaders(w, true)
	if err := h.tmpl.ExecuteTemplate(w, "prefs.html", data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func (h *Handler) postPrefs(w http.ResponseWriter, r *http.Request, token string) {
	if !h.checkCSRF(r, token) {
		http.Error(w, "csrf failed", http.StatusForbidden)
		return
	}
	if h.prefs == nil {
		http.Error(w, "prefs unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	// Collect any kind_<name>=<action> fields. An empty action means
	// "follow the default" — clear the override.
	current, _ := h.prefs.Load()
	if current.Kinds == nil {
		current.Kinds = make(map[string]prefs.KindPref)
	}
	for _, row := range prefsRows {
		field := "kind_" + row.Kind
		val := r.PostFormValue(field)
		val = strings.TrimSpace(val)
		if val == "" {
			delete(current.Kinds, row.Kind)
			continue
		}
		current.Kinds[row.Kind] = prefs.KindPref{Action: val}
	}
	if err := h.prefs.Save(current); err != nil {
		h.renderPrefs(w, r, token, "Save failed: "+err.Error())
		return
	}
	http.Redirect(w, r, "/admin/prefs", http.StatusSeeOther)
}

// renderLogs serves GET /admin/logs — the log tab shown in the browser.
// The heavy lifting (reading the file) happens client-side via
// /admin/api/logs so the "Refresh" button doesn't require a full page
// reload.
func (h *Handler) renderLogs(w http.ResponseWriter, r *http.Request) {
	path, _ := log.DefaultLogFile()
	text, _ := tailLogFile(path, 200)
	data := struct {
		Now     string
		Version string
		LogPath string
		LogText string
	}{
		Now:     time.Now().UTC().Format(time.RFC3339),
		Version: h.version,
		LogPath: path,
		LogText: text,
	}
	h.writeSecurityHeaders(w, false)
	if err := h.tmpl.ExecuteTemplate(w, "logs.html", data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// getAPILogs serves GET /admin/api/logs?n=N as plain text — the last N
// lines of cloakline's own log file, already redacted before it was
// written (see internal/obs/log). This is what a user copies and pastes
// when asking for help debugging.
func (h *Handler) getAPILogs(w http.ResponseWriter, r *http.Request) {
	n := 200
	if s := r.URL.Query().Get("n"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 && v <= 5000 {
			n = v
		}
	}
	path, err := log.DefaultLogFile()
	if err != nil {
		http.Error(w, "log path unavailable", http.StatusInternalServerError)
		return
	}
	text, err := tailLogFile(path, n)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err != nil {
		if os.IsNotExist(err) {
			_, _ = w.Write([]byte("(no log file yet — nothing has been written)"))
			return
		}
		_, _ = w.Write([]byte("(failed to read log file: " + err.Error() + ")"))
		return
	}
	_, _ = w.Write([]byte(text))
}

// tailLogFile returns the last n lines of the file at path. The rotating
// writer in internal/obs/log caps each file at 10MB, so reading it whole
// and slicing in memory is cheap enough to not need a streaming reader.
func tailLogFile(path string, n int) (string, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	text := strings.TrimRight(string(buf), "\n")
	if text == "" {
		return "", nil
	}
	lines := strings.Split(text, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n"), nil
}

// getSessionAllow handles GET /admin/session/allow?nonce=<hex>.
// The URL is embedded in the system notification balloon tip; clicking
// "Allow session" opens it in the default browser. No CSRF token
// required — the nonce is single-use, expires in 5 minutes, and only
// grants a session opt-out (not a privileged write operation).
func (h *Handler) getSessionAllow(w http.ResponseWriter, r *http.Request) {
	nonce := strings.TrimSpace(r.URL.Query().Get("nonce"))

	h.nonceMu.Lock()
	entry, ok := h.nonces[nonce]
	if ok {
		// Single-use: consume immediately.
		delete(h.nonces, nonce)
		// Reject if expired (belt-and-suspenders; lazy eviction in
		// IssueNonce usually handles this).
		if time.Since(entry.issued) > nonceTTL {
			ok = false
		}
	}
	h.nonceMu.Unlock()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")

	if !ok {
		w.WriteHeader(http.StatusGone)
		_, _ = w.Write([]byte(sessionAllowExpiredPage))
		return
	}

	// Grant opt-out on the tlsinspect handler.
	if h.sessionOptOut != nil {
		h.sessionOptOut.OptOutSession(entry.sessionKey)
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(sessionAllowOKPage))
}

const sessionAllowOKPage = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>cloakline · Session allowed</title>
  <style>
    *{box-sizing:border-box}
    body{margin:0;background:#0f1115;color:#e6e6ea;font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}
    .card{background:#171923;border:1px solid #262a36;border-radius:12px;padding:36px 44px;max-width:440px;text-align:center}
    .icon{font-size:52px;margin-bottom:18px}
    h1{font-size:20px;font-weight:600;margin:0 0 12px}
    p{color:#a0a4b4;font-size:14px;margin:0 0 20px}
    a{color:#55c8e0;text-decoration:none}
    a:hover{text-decoration:underline}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">&#x1F6E1;</div>
    <h1>Session allowed</h1>
    <p>cloakline will pass high-tier content through unredacted for this session
    (up to 1 hour). Close this tab, go back to Claude, and <strong>resend your
    original message</strong>.</p>
    <p><a href="/admin">Open dashboard</a></p>
  </div>
</body>
</html>`

const sessionAllowExpiredPage = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>cloakline · Link expired</title>
  <style>
    *{box-sizing:border-box}
    body{margin:0;background:#0f1115;color:#e6e6ea;font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}
    .card{background:#171923;border:1px solid #262a36;border-radius:12px;padding:36px 44px;max-width:440px;text-align:center}
    .icon{font-size:52px;margin-bottom:18px}
    h1{font-size:20px;font-weight:600;margin:0 0 12px}
    p{color:#a0a4b4;font-size:14px;margin:0 0 20px}
    a{color:#55c8e0;text-decoration:none}
    a:hover{text-decoration:underline}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">&#x23F3;</div>
    <h1>Link expired or already used</h1>
    <p>Allow links are single-use and expire after 5 minutes. Trigger another
    detection to get a fresh link, or visit the
    <a href="/admin">admin dashboard</a> to manage session settings.</p>
  </div>
</body>
</html>`

// funcs are the template helpers.
func funcs() template.FuncMap {
	return template.FuncMap{
		"fmtTime": func(t time.Time) string {
			return t.UTC().Format("2006-01-02 15:04:05Z")
		},
		"join": func(ss []string, sep string) string {
			return strings.Join(ss, sep)
		},
		"verdictClass": func(v audit.Verdict) string {
			switch v {
			case audit.VerdictAllowed:
				return "v-allow"
			case audit.VerdictRedacted:
				return "v-redact"
			case audit.VerdictWarned:
				return "v-warn"
			case audit.VerdictBlockedDLP, audit.VerdictBlockedPolicy:
				return "v-block"
			case audit.VerdictAuthFailed:
				return "v-auth"
			case audit.VerdictUpstreamError, audit.VerdictError:
				return "v-err"
			}
			return "v-other"
		},
		"truncate": func(s string, n int) string {
			if len(s) <= n {
				return s
			}
			return s[:n] + "…"
		},
	}
}

// getAPIStatus serves GET /admin/api/status as JSON for the `cloak tail`
// live dashboard. All fields are already redacted metadata — no plaintext.
func (h *Handler) getAPIStatus(w http.ResponseWriter, r *http.Request) {
	stats := h.recorder.Stats()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(stats)
}

// apiEntry is the safe JSON shape of a recent audit entry. Only metadata
// fields are included — no plaintext content is ever serialised.
type apiEntry struct {
	Timestamp   string   `json:"timestamp"`
	Verdict     string   `json:"verdict"`
	Endpoint    string   `json:"endpoint"`
	Model       string   `json:"model"`
	DLPFindings []string `json:"dlp_findings"`
	DurationMS  int64    `json:"duration_ms"`
}

// getAPIRecent serves GET /admin/api/recent?n=N as JSON.
func (h *Handler) getAPIRecent(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if s := r.URL.Query().Get("n"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 100 {
			limit = n
		}
	}
	entries := h.recorder.Recent(limit)
	out := make([]apiEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, apiEntry{
			Timestamp:   e.Timestamp.UTC().Format(time.RFC3339),
			Verdict:     string(e.Verdict),
			Endpoint:    e.Endpoint,
			Model:       e.Model,
			DLPFindings: e.DLPFindings,
			DurationMS:  e.DurationMS,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(out)
}

// getAPIConnectivity serves GET /admin/api/connectivity as JSON.
// It probes the real Anthropic API through the passthrough transport and
// reports whether traffic can flow. A 4xx from Anthropic counts as reachable.
func (h *Handler) getAPIConnectivity(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	if h.connectivityProbe == nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "probe not available"})
		return
	}

	latencyMS, err := h.connectivityProbe.ProbeConnectivity(r.Context())
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":         false,
			"latency_ms": latencyMS,
			"error":      err.Error(),
		})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":         true,
		"latency_ms": latencyMS,
	})
}

// humanizeDuration renders a rough time-saved figure. Precision is not
// the point — the tile is a vanity metric.
func humanizeDuration(d time.Duration) string {
	if d <= 0 {
		return "0m"
	}
	h := int(d.Hours())
	m := int(d.Minutes()) - h*60
	switch {
	case h >= 24:
		days := h / 24
		return strconv.Itoa(days) + "d " + strconv.Itoa(h%24) + "h"
	case h > 0:
		return strconv.Itoa(h) + "h " + strconv.Itoa(m) + "m"
	default:
		return strconv.Itoa(m) + "m"
	}
}
