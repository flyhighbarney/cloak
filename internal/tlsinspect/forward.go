package tlsinspect

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"cloakline/internal/api"
	"cloakline/internal/audit"
	"cloakline/internal/crypto/aesbox"
	"cloakline/internal/dlp/patterns"
	"cloakline/internal/obs/log"
	"cloakline/internal/stage/injection"
	"cloakline/internal/stage/intent"
)

// Handler applies the inspection pipeline to a single request/response.
//
// Flow:
//   1. Read the request body into memory (up to MaxBodyBytes).
//   2. Extract prompt text from the JSON body (Anthropic + OpenAI shapes).
//   3. Run the injection rule set. High-score → 403 to client, no forward.
//   4. Run DLP patterns. HIGH-tier findings (api_key, aws_key, password, etc.)
//      are one-way redacted to static markers ([REDACTED_PASSWORD] etc.) and
//      the user is notified via a system notification (Windows balloon tip).
//      MEDIUM-tier findings (email, SSN, phone) are round-trip tokenized so
//      Claude's response uses the real values again. LOW-tier findings are
//      forwarded unchanged and flagged on the dashboard.
//   5. Forward the modified body to the real host with the ORIGINAL
//      auth headers untouched.
//   6. On response, walk the body and swap pseudonyms back to originals
//      so the CLI sees its real values.
//
// If the user clicks "Allow session" in the notification (opens an admin URL),
// subsequent requests from the same session bypass HIGH-tier redaction for
// one hour. Use OptOutSession to grant that permission programmatically.
type Handler struct {
	logger        *log.Logger
	meter         MeterFacade
	forwardClient *http.Client
	maxBodyBytes  int64

	dlpActions dlpActionResolver // per-kind action policy (config)
	prefs      prefsSource       // per-kind override (dashboard, runtime)
	injRules   []injection.Rule
	injScore   int // threshold; sum > threshold → block

	// confirm tracks per-session opt-outs (user clicked "Allow session").
	// It no longer stores pending bodies — the old y/n CLI prompt flow
	// has been replaced by a system notification + admin URL.
	confirm *confirmStore

	// notifyFn is called (at most once per request) after a HIGH-tier
	// redact_one_way fires. It receives the kind name (e.g. "password")
	// and the session key, and is expected to fire a user-visible alert.
	// nil = no notification (safe default, used in tests).
	notifyFn func(kind, sessionKey string)

	// flog collapses repeated forward-path errors so a retry storm can't
	// bury real warnings under thousands of identical lines. See logdedup.go.
	flog *forwardLogLimiter

	// recorder receives one content-free audit entry per inspected CHAT
	// request, so the admin dashboard / `cloakline tail` reflect the
	// transparent :443 path (not just the :4000 gateway). nil disables
	// recording — safe for tests. See recorderFacade.
	recorder recorderFacade
}

// recorderFacade is the subset of *audit.Recorder the handler needs. Kept as
// an interface so tests can omit it (nil) and so the handler never depends on
// recorder internals. Entries are content-free: finding KINDS and a verdict,
// never plaintext.
type recorderFacade interface {
	Record(audit.Entry)
}

// MeterFacade is the subset of the meter interface this handler needs.
// Kept as a facade so tests can plug in a no-op meter.
type MeterFacade interface {
	Counter(name api.MetricName, dims map[api.DimKey]string)
}

// dlpActionResolver maps a finding kind to an action.
// Recognised strings: "allow" | "warn" | "redact" | "block" | "redact_one_way".
// An empty string or unknown value defers to defaultActionForKind.
type dlpActionResolver interface {
	Action(kind string) string
}

// prefsSource is the runtime override layer (dashboard-managed).
// It is consulted BEFORE the config-file dlpActionResolver so users
// can tweak behavior without editing YAML or restarting.
type prefsSource interface {
	ActionForKind(kind string) (string, bool)
}

// defaultActionForKind is the fallback when no rule is configured. It
// encodes the tiered policy the user asked for (see docs/policy-tiers.md):
//
//   HIGH   → redact_one_way (credential markers, never restored)
//   MEDIUM → redact          (round-trip via vault)
//   LOW    → allow           (flag on dashboard, never modify)
func defaultActionForKind(kind string) string {
	switch kind {
	case string(api.PIIAPIKey), string(api.PIIAWSKey), string(api.PIIGitHubToken),
		string(api.PIIPrivateKey), string(api.PIICreditCard), string(api.PIIPassword):
		return "redact_one_way"
	case string(api.PIISSN), string(api.PIIEmail), string(api.PIIPhone):
		return "redact"
	case string(api.PIIIPAddress), string(api.PIIURLPath), string(api.PIIPersonName):
		return "allow"
	}
	return "allow"
}

// resolveAction returns the effective action for kind. Order:
//
//  1. Dashboard prefs override (runtime, no restart needed).
//  2. rules.yaml action from the config-file resolver.
//  3. Tiered default (defaultActionForKind).
func (h *Handler) resolveAction(kind string) string {
	if h.prefs != nil {
		if a, ok := h.prefs.ActionForKind(kind); ok && a != "" {
			return a
		}
	}
	if h.dlpActions != nil {
		if a := h.dlpActions.Action(kind); a != "" && a != "unknown" {
			return a
		}
	}
	return defaultActionForKind(kind)
}

// HandlerConfig is the constructor input.
type HandlerConfig struct {
	Logger        *log.Logger
	Meter         MeterFacade
	MaxBodyBytes  int64
	DLPActions    dlpActionResolver
	Prefs         prefsSource // optional; runtime dashboard overrides
	InjectionRules []injection.Rule
	InjectionThreshold int
	Recorder      recorderFacade // optional; nil disables dashboard recording
}

// NewHandler assembles a handler.
func NewHandler(c HandlerConfig) *Handler {
	if c.MaxBodyBytes == 0 {
		c.MaxBodyBytes = 4 << 20
	}
	if c.InjectionThreshold == 0 {
		c.InjectionThreshold = 50
	}
	if len(c.InjectionRules) == 0 {
		c.InjectionRules = injection.BuiltinRules()
	}
	// Initialise the confirmation store. Failure to mint the AES key
	// is non-fatal — we log and continue with confirm disabled, since
	// the rest of the DLP pipeline still works (one-way redaction).
	confirm, cerr := newConfirmStore()
	if cerr != nil && c.Logger != nil {
		c.Logger.Warn("tlsinspect.confirm_disabled", log.Fields{"error": cerr.Error()})
	}
	return &Handler{
		logger:       c.Logger,
		meter:        c.Meter,
		maxBodyBytes: c.MaxBodyBytes,
		dlpActions:   c.DLPActions,
		prefs:        c.Prefs,
		injRules:     c.InjectionRules,
		injScore:     c.InjectionThreshold,
		confirm:      confirm,
		flog:         newForwardLogLimiter(10 * time.Second),
		recorder:     c.Recorder,
		forwardClient: &http.Client{
			Timeout: 120 * time.Second,
			// Bypass the hosts-file redirect that transparent interception
			// installs. Without this, api.anthropic.com resolves to
			// 127.0.0.1 for OUR process too and we loop into our own
			// listener (see resolver.go). The bootstrap resolver dials the
			// real upstream IP instead.
			Transport: newForwardTransport(newBootstrapResolver()),
		},
	}
}

// MaxBodyBytes returns the configured request-body cap. Used by the
// failsafe path in server.go, which must buffer the body itself so it
// can replay the request upstream if the inspection pipeline panics.
func (h *Handler) MaxBodyBytes() int64 { return h.maxBodyBytes }

// FailOpen forwards an untouched request straight to the real upstream with
// zero inspection. It is the automatic failsafe: if the inspection pipeline
// panics mid-request, the server recovers and calls this so the user's AI
// request still succeeds instead of dying on a half-written response. This
// preserves cloakline's core promise — the guard failing must never break
// Claude Code.
func (h *Handler) FailOpen(w http.ResponseWriter, r *http.Request, host string, body []byte) {
	h.forwardPassthrough(w, r, host, body)
}

// SetNotifyFunc sets the callback fired after a HIGH-tier redact_one_way
// fires (at most once per request). fn receives the kind name and the
// session key for the current request. The caller typically uses these
// to issue a one-time nonce and show a platform notification. Safe to
// call before the first request; not safe to call concurrently with
// Handle.
func (h *Handler) SetNotifyFunc(fn func(kind, sessionKey string)) {
	h.notifyFn = fn
}

// OptOutSession grants sessionKey one-hour permission to bypass HIGH-tier
// redaction. Called by the admin allow-session endpoint when the user
// clicks "Allow session" in a notification.
func (h *Handler) OptOutSession(sessionKey string) {
	if h.confirm != nil {
		h.confirm.OptOut(sessionKey)
	}
}

// Handle is the ServeHTTP body split out from server.go for readability.
func (h *Handler) Handle(w http.ResponseWriter, r *http.Request, host string) {
	start := time.Now()
	// 1. Read request body.
	body, err := io.ReadAll(io.LimitReader(r.Body, h.maxBodyBytes+1))
	if err != nil {
		http.Error(w, `{"error":"read body failed"}`, http.StatusBadRequest)
		return
	}
	if int64(len(body)) > h.maxBodyBytes {
		http.Error(w, `{"error":"body too large"}`, http.StatusRequestEntityTooLarge)
		return
	}

	// 1a. Scope check. cloakline only scans CHAT endpoints — the ones
	//     that actually carry user prompts. Everything else (OAuth
	//     token refresh, model listings, health/status, embeddings,
	//     files, moderation, etc.) passes through untouched. Without
	//     this, cloakline's injection scorer can 403 a random OAuth
	//     refresh whose body happens to hit an injection rule word
	//     — breaking Claude Code auth entirely (see the incident in
	//     docs/session-notes.md).
	if !isChatEndpoint(r.URL.Path) {
		h.forwardPassthrough(w, r, host, body)
		return
	}

	// Best-effort model name for the audit entry (content-free).
	model := extractModel(body)

	// 2. Derive session key for opt-out tracking. Used by the redaction
	//    loop (step 5) to check whether this session clicked "Allow" in
	//    the notification, and by notifyFn to correlate the allow-URL
	//    nonce back to this session.
	sessionKey := SessionKey(r.Header.Get("Authorization"), r.Header.Get("x-api-key"))

	// 3. Extract prompt text and run injection scorer.
	// Only the latest user message is scored — prior turns were already
	// scanned on their own turn. Scoring the full history causes false
	// positives when earlier turns legitimately contain injection-like text
	// (e.g. a user asking Claude to explain injection attacks, or cloakline's
	// own test fixtures appearing in the accumulated context window).
	pieces := extractPromptText(body)
	joined := strings.Join(pieces, "\n")
	latest := extractLastUserPrompt(body)
	injText := latest
	if injText == "" {
		injText = joined
	}
	if injText != "" {
		result := injection.Score(injText, h.injRules)
		if result.Score >= h.injScore {
			h.logger.Warn("tlsinspect.injection_blocked", log.Fields{
				"host":  host,
				"score": result.Score,
			})
			var ruleIDs []string
			for _, m := range result.Matches {
				ruleIDs = append(ruleIDs, m.RuleID)
			}
			h.record(r, host, model, start, audit.VerdictBlockedPolicy, nil, result.Score, ruleIDs, "")
			http.Error(w, `{"error":"content blocked by policy","reason":"injection"}`, http.StatusForbidden)
			return
		}
	}

	// 4. DLP scan. Only the LATEST user message is scanned for findings
	//    (prior turns were already processed on their own turn). But
	//    the replacement in step 5 still replaces on the WHOLE body —
	//    so plaintext that Claude Code kept in its client-side chat log
	//    gets scrubbed defensively even if we didn't scan history for
	//    detection.
	scanText := latest
	if scanText == "" {
		scanText = joined
	}
	scanned := patterns.Scan(scanText)
	for _, r := range intent.FindPasswordCandidates(scanText) {
		scanned = append(scanned, patterns.Finding{
			Kind:  api.PIIPassword,
			Start: r[0],
			End:   r[1],
			Text:  scanText[r[0]:r[1]],
		})
	}
	for _, f := range scanned {
		if h.resolveAction(string(f.Kind)) == "block" {
			h.logger.Warn("tlsinspect.dlp_blocked", log.Fields{
				"host": host,
				"kind": string(f.Kind),
			})
			h.record(r, host, model, start, audit.VerdictBlockedDLP, []string{string(f.Kind)}, 0, nil, "")
			http.Error(w, `{"error":"content blocked by policy","reason":"dlp","kind":"`+string(f.Kind)+`"}`, http.StatusForbidden)
			return
		}
	}

	// 5. Apply redaction.
	//    - redact_one_way: replace with a static marker ([REDACTED_PASSWORD]
	//      etc.). Plaintext is gone. A system notification fires the first
	//      time this happens in a request, giving the user an "Allow session"
	//      button that grants a 1-hour opt-out for HIGH-tier findings.
	//    - redact (round-trip): tokenize via vault; pseudonym restored in
	//      the response so Claude's reply shows real values.
	//    - allow / warn: body unchanged; finding is flagged on dashboard.
	//
	//    If the session has an active opt-out (user clicked "Allow session"),
	//    HIGH-tier findings are passed through unmodified for the opt-out
	//    window — matching what the notification says will happen.
	sessionOptedOut := h.confirm != nil && sessionKey != "" && h.confirm.IsOptedOut(sessionKey)
	vault := newLocalVault()
	// Redaction-safe tallies for the forwarded log line: what was detected
	// (by kind) and what we did about it. Kind names and counts only — never
	// the matched plaintext — so a user can confirm e.g. a password was
	// one-way redacted without the secret ever reaching the log.
	kinds := make(map[string]int, 8)
	var nOneWay, nTokenized, nAllowed, nSkippedOptOut int
	var notifiedOnce bool

	// Build a replacement table first, then apply all substitutions in a
	// single pass via strings.NewReplacer (Aho-Corasick internally), instead
	// of calling bytes.ReplaceAll once per finding which is O(body × findings).
	// pairs is [old, new, old, new, ...] as required by strings.NewReplacer.
	pairs := make([]string, 0, len(scanned)*2)
	for _, f := range scanned {
		kinds[string(f.Kind)]++
		action := h.resolveAction(string(f.Kind))
		if sessionOptedOut && api.TierForKind(f.Kind) == api.TierHigh {
			nSkippedOptOut++
			continue
		}
		switch action {
		case "redact", "warn":
			pseudo := vault.tokenize(string(f.Kind), f.Text)
			pairs = append(pairs, f.Text, pseudo)
			nTokenized++
		case "redact_one_way":
			marker := api.StaticMarkerForKind(f.Kind)
			pairs = append(pairs, f.Text, marker)
			nOneWay++
			if !notifiedOnce && h.notifyFn != nil && sessionKey != "" {
				notifiedOnce = true
				h.notifyFn(string(f.Kind), sessionKey)
			}
		default:
			nAllowed++
		}
	}
	newBody := body
	if len(pairs) > 0 {
		newBody = []byte(strings.NewReplacer(pairs...).Replace(string(body)))
	}

	// 6. Forward to the real host.
	upstreamURL := "https://" + host + r.URL.RequestURI()
	req, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, bytes.NewReader(newBody))
	if err != nil {
		http.Error(w, `{"error":"forward failed"}`, http.StatusBadGateway)
		return
	}
	// Copy every request header — user's auth passes through untouched.
	for k, v := range r.Header {
		if strings.EqualFold(k, "Host") {
			continue
		}
		req.Header[k] = v
	}
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(newBody)))

	resp, err := h.forwardClient.Do(req)
	if err != nil {
		h.logForwardErr("tlsinspect.forward_failed", host, r.URL.Path, err)
		http.Error(w, `{"error":"upstream unreachable"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 7. Response: read, restore pseudonyms, write.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		http.Error(w, `{"error":"read response failed"}`, http.StatusBadGateway)
		return
	}
	restored := vault.restore(respBody)

	// Copy response headers.
	for k, v := range resp.Header {
		if strings.EqualFold(k, "Content-Length") {
			continue
		}
		w.Header()[k] = v
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(restored)))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(restored)

	fwdFields := log.Fields{
		"host":      host,
		"status":    resp.StatusCode,
		"in_bytes":  len(body),
		"out_bytes": len(newBody),
		"findings":  len(scanned),
	}
	if len(scanned) > 0 {
		// Only attach the breakdown when something was actually found, so a
		// healthy no-finding forward stays terse. Values are kind/action
		// names and counts, never plaintext. Read it as: "redacted_one_way">0
		// with "password" present in "kinds" proves a password was scrubbed
		// before the body left the machine; "skipped_optout">0 means a
		// HIGH-tier finding was deliberately passed through under an active
		// "Allow session" opt-out.
		fwdFields["kinds"] = summarizeKinds(kinds)
		fwdFields["redacted_one_way"] = nOneWay
		fwdFields["tokenized"] = nTokenized
		fwdFields["allowed"] = nAllowed
		if nSkippedOptOut > 0 {
			fwdFields["skipped_optout"] = nSkippedOptOut
		}
	}
	h.logger.Info("tlsinspect.forwarded", fwdFields)

	dlpKinds := make([]string, 0, len(kinds))
	for k := range kinds {
		dlpKinds = append(dlpKinds, k)
	}
	verdict := audit.VerdictFromError(nil, nOneWay+nTokenized > 0, false)
	h.record(r, host, model, start, verdict, dlpKinds, 0, nil, "")
}

// record appends a content-free audit entry for this request, if a recorder
// is configured. Never pass plaintext findings — only kind names, rule IDs,
// and the resolved verdict.
func (h *Handler) record(r *http.Request, host, model string, start time.Time, verdict audit.Verdict, dlpFindings []string, injScore int, injRules []string, errMsg string) {
	if h.recorder == nil {
		return
	}
	h.recorder.Record(audit.Entry{
		Endpoint:       r.URL.Path,
		Mode:           "unary",
		Upstream:       host,
		Model:          model,
		Verdict:        verdict,
		DLPFindings:    dlpFindings,
		InjectionScore: injScore,
		InjectionRules: injRules,
		DurationMS:     time.Since(start).Milliseconds(),
		Error:          errMsg,
	})
}

// isChatEndpoint reports whether the request path is one of the
// endpoints that actually carries chat/prompt content. Only these
// enter the DLP + injection + confirmation pipeline. Everything else
// (OAuth token refresh, listing models, embeddings, moderation,
// health, etc.) passes through untouched so cloakline can't
// accidentally break provider auth or API discovery calls.
func isChatEndpoint(path string) bool {
	p := strings.ToLower(path)
	switch {
	case strings.HasPrefix(p, "/v1/messages"):          // Anthropic chat
		return true
	case strings.HasPrefix(p, "/v1/chat/completions"):  // OpenAI chat
		return true
	case strings.HasPrefix(p, "/v1/completions"):       // OpenAI legacy text-completion
		return true
	case strings.HasPrefix(p, "/v1/responses"):         // OpenAI new Responses API
		return true
	}
	return false
}

// forwardPassthrough sends the request to the real upstream with
// zero inspection. Used by non-chat endpoints so cloakline stays out
// of the way of provider auth, model listings, etc.
func (h *Handler) forwardPassthrough(w http.ResponseWriter, r *http.Request, host string, body []byte) {
	upstreamURL := "https://" + host + r.URL.RequestURI()
	req, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, bytes.NewReader(body))
	if err != nil {
		http.Error(w, `{"error":"forward failed"}`, http.StatusBadGateway)
		return
	}
	for k, v := range r.Header {
		if strings.EqualFold(k, "Host") {
			continue
		}
		req.Header[k] = v
	}
	if len(body) > 0 {
		req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	}
	resp, err := h.forwardClient.Do(req)
	if err != nil {
		h.logForwardErr("tlsinspect.passthrough_failed", host, r.URL.Path, err)
		http.Error(w, `{"error":"upstream unreachable"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		http.Error(w, `{"error":"read response failed"}`, http.StatusBadGateway)
		return
	}
	for k, v := range resp.Header {
		if strings.EqualFold(k, "Content-Length") {
			continue
		}
		w.Header()[k] = v
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(respBody)))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
}

// logForwardErr records a failed upstream forward at a severity that matches
// the cause. A client-cancelled request (context.Canceled) or a deadline that
// fired because the caller went away is normal churn — Claude Desktop cancels
// every in-flight request at once when it restarts or switches models, which
// otherwise floods the log with thousands of near-identical warnings for a
// non-event. Those go to Debug. Everything else (real upstream unreachability,
// TLS failures, resolver errors) stays at Warn.
//
// On top of the severity split, repeated errors are deduplicated per
// (msg, host, coarse-path, error-class) so a retry storm collapses to one line
// per window carrying a "repeated" count, instead of thousands of identical
// records that would bury a genuinely useful warning. See logdedup.go.
func (h *Handler) logForwardErr(msg, host, path string, err error) {
	if h.logger == nil {
		return
	}
	debugLevel := errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)

	emit, count := true, 1
	if h.flog != nil {
		key := msg + "|" + host + "|" + coarsePath(path) + "|" + errClass(err)
		emit, count = h.flog.record(time.Now(), key)
	}
	if !emit {
		return
	}

	fields := log.Fields{"host": host, "path": path, "err": err.Error()}
	if count > 1 {
		// This one line stands in for `count` occurrences observed in the
		// last window; without this the same storm would be `count` lines.
		fields["repeated"] = count
		fields["window_sec"] = int(h.flog.window / time.Second)
	}
	if debugLevel {
		h.logger.Debug(msg, fields)
		return
	}
	h.logger.Warn(msg, fields)
}

// forwardBody forwards an already-approved body upstream 1:1 and
// zeroizes the plaintext slice when the Transport is provably done
// with it.
//
// Zeroize timing — finding #8: we call aesbox.Zeroize(body) at the
// EXACT point where the Transport has finished reading the request
// body: immediately after forwardClient.Do() returns. Do() is
// synchronous with respect to sending — the Transport (including any
// internal retry reads via the bytes.Reader seeker) has consumed every
// byte of body before returning, whether the call succeeded or failed.
// We do NOT use defer-at-top-of-function because a top-level defer
// fires at function exit, which requires the reader to trace LIFO
// defer ordering to confirm the timing is safe. Explicit beats subtle.
//
// Callers must not zeroize body themselves — double-zeroize is harmless
// but the risk is the caller zeroizing TOO EARLY (before Do returns).
func (h *Handler) forwardBody(w http.ResponseWriter, r *http.Request, host string, body []byte) error {
	upstreamURL := "https://" + host + r.URL.RequestURI()
	req, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, bytes.NewReader(body))
	if err != nil {
		// Do() never ran; Transport never touched body. Safe to zeroize.
		aesbox.Zeroize(body)
		http.Error(w, `{"error":"forward failed"}`, http.StatusBadGateway)
		return err
	}
	for k, v := range r.Header {
		if strings.EqualFold(k, "Host") {
			continue
		}
		req.Header[k] = v
	}
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))

	resp, err := h.forwardClient.Do(req)
	// Transport is done with body — zeroize immediately regardless of
	// success or failure. Everything below this line touches respBody,
	// not body.
	aesbox.Zeroize(body)
	if err != nil {
		http.Error(w, `{"error":"upstream unreachable"}`, http.StatusBadGateway)
		return err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		http.Error(w, `{"error":"read response failed"}`, http.StatusBadGateway)
		return err
	}
	for k, v := range resp.Header {
		if strings.EqualFold(k, "Content-Length") {
			continue
		}
		w.Header()[k] = v
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(respBody)))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
	return nil
}

// -------- Prompt text extraction --------

// extractPromptText walks the JSON body of an AI API call and returns
// every text-shaped user-content string. Supports OpenAI Chat Completions
// and Anthropic Messages formats. Non-JSON bodies return [].
func extractPromptText(body []byte) []string {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return nil
	}
	var out []string
	walkJSON(v, func(s string) { out = append(out, s) })
	return out
}

// extractLastUserPrompt returns the text of ONLY the last user message
// in an Anthropic or OpenAI request body. Used for turn-by-turn intent
// checks that must not re-trigger on flagged content already in the
// conversation history. Non-JSON or missing-messages bodies return "".
func extractLastUserPrompt(body []byte) string {
	// Try Anthropic shape first: {"messages":[{"role":"user","content":...}]}.
	var probe struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return ""
	}
	// Walk backwards to the most recent user turn.
	for i := len(probe.Messages) - 1; i >= 0; i-- {
		m := probe.Messages[i]
		if m.Role != "user" {
			continue
		}
		// content can be a bare string or a list of blocks.
		var s string
		if err := json.Unmarshal(m.Content, &s); err == nil {
			return s
		}
		var blocks []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if err := json.Unmarshal(m.Content, &blocks); err == nil {
			var b strings.Builder
			for _, blk := range blocks {
				if blk.Type == "text" {
					if b.Len() > 0 {
						b.WriteByte('\n')
					}
					b.WriteString(blk.Text)
				}
			}
			return b.String()
		}
		return ""
	}
	return ""
}

// walkJSON descends into the object and pulls every "content" / "text" /
// "input" string. We're deliberately generous — better to over-scan than miss.
func walkJSON(v any, emit func(string)) {
	switch n := v.(type) {
	case map[string]any:
		for k, val := range n {
			switch k {
			case "content", "text", "input", "prompt", "system", "assistant":
				if s, ok := val.(string); ok {
					emit(s)
				}
			}
			walkJSON(val, emit)
		}
	case []any:
		for _, x := range n {
			walkJSON(x, emit)
		}
	}
}

// -------- Per-request vault (no cross-request state) --------

type localVault struct {
	fwd map[string]string // pseudonym -> original
}

func newLocalVault() *localVault { return &localVault{fwd: make(map[string]string, 4)} }

func (v *localVault) tokenize(kind, plaintext string) string {
	// [KIND_seq_random] — matches dlptier1.DeAnonymize's pattern shape.
	buf := make([]byte, 6)
	_, _ = rand.Read(buf)
	pseudo := fmt.Sprintf("[%s_%d_%s]",
		strings.ToUpper(kind),
		len(v.fwd)+1,
		hex.EncodeToString(buf),
	)
	v.fwd[pseudo] = plaintext
	return pseudo
}

func (v *localVault) restore(body []byte) []byte {
	if len(v.fwd) == 0 {
		return body
	}
	out := body
	for pseudo, orig := range v.fwd {
		out = bytes.ReplaceAll(out, []byte(pseudo), []byte(orig))
	}
	return out
}
