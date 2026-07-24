// Package adminui serves the read-only /admin dashboard.
//
// Server-rendered HTML, no JavaScript framework, no build step. One embedded
// template. Renders in constant time relative to the ring buffer size.
package adminui

import (
	"embed"
	_ "embed"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"policyd/internal/audit"
)

//go:embed templates/*.html
var templatesFS embed.FS

// Handler serves /admin. It's a plain http.Handler; the transport plugs it
// into the admin listener (:4001).
type Handler struct {
	recorder *audit.Recorder
	tmpl     *template.Template
	version  string
}

// New constructs the admin handler.
func New(recorder *audit.Recorder, version string) (*Handler, error) {
	tmpl, err := template.New("admin").Funcs(funcs()).ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Handler{recorder: recorder, tmpl: tmpl, version: version}, nil
}

// ServeHTTP renders the dashboard. Only GET is supported.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limit := 100
	if s := r.URL.Query().Get("n"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	entries := h.recorder.Recent(limit)
	stats := h.recorder.Stats()

	data := struct {
		Now     string
		Version string
		Stats   audit.Stats
		Entries []audit.Entry
		Limit   int
	}{
		Now:     time.Now().UTC().Format(time.RFC3339),
		Version: h.version,
		Stats:   stats,
		Entries: entries,
		Limit:   limit,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	// Basic CSP: only what this page ships. No inline scripts.
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'")

	if err := h.tmpl.ExecuteTemplate(w, "dashboard.html", data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

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
