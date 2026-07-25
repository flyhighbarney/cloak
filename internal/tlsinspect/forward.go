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
	"cloakline/internal/stage/intent"
)

// Handler applies the inspection pipeline to a single request/response.
//
// Flow:
//   1. Read the request body into memory (up to MaxBodyBytes).
//   2. Non-chat endpoints (OAuth, model listing, etc.) pass through untouched.
//   3. DLP scan on the latest user message only. HIGH-tier findings (api_key,
//      aws_key, password, etc.) are one-way redacted to static markers and the
//      user is notified via a system notification (Windows balloon tip). MEDIUM-
//      tier findings (email, SSN, phone) are round-trip tokenized. LOW-tier
//      findings pass through and are flagged on the dashboard.
//   4. Forward the modified body to the real host with ORIGINAL auth untouched.
//   5. On response, swap pseudonyms back so the CLI sees its real values.
//
// If the user clicks "Allow session" in the notification (opens an admin URL),
// subsequent requests from the same session bypass HIGH-tier redaction for
// one hour. Use OptOutSession to grant that permission programmatically.
type Handler struct {
	logger        *log.Logger
	meter         MeterFacade
	forwardClient *http.Client
	// passthroughClient is used for non-chat endpoints (auth, telemetry, model
	// listings, etc.). It never pools connections — each request gets a fresh
	// TLS handshake — so stale pooled connections cannot cause "bad record MAC"
	// errors on auth refreshes, which Claude Code surfaces as "failed to
	// authenticate". Chat requests use forwardClient (pooled) for streaming
	// performance; passthrough requests favour correctness over latency.
	passthroughClient *http.Client
	maxBodyBytes      int64

	dlpActions dlpActionResolver // per-kind action policy (config)
	prefs      prefsSource       // per-kind override (dashboard, runtime)
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
	Recorder      recorderFacade // optional; nil disables dashboard recording
}

// NewHandler assembles a handler.
func NewHandler(c HandlerConfig) *Handler {
	if c.MaxBodyBytes == 0 {
		c.MaxBodyBytes = 4 << 20
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
		confirm:      confirm,
		flog:     newForwardLogLimiter(10 * time.Second),
		recorder: c.Recorder,
		forwardClient: &http.Client{
			Timeout: 120 * time.Second,
			// Bypass the hosts-file redirect that transparent interception
			// installs. Without this, api.anthropic.com resolves to
			// 127.0.0.1 for OUR process too and we loop into our own
			// listener (see resolver.go). The bootstrap resolver dials the
			// real upstream IP instead.
			Transport: newForwardTransport(newBootstrapResolver()),
		},
		// passthroughClient intentionally disables connection pooling.
		// Non-chat endpoints (OAuth token refresh, model listing, telemetry)
		// are infrequent but must never fail due to a stale pooled connection
		// returning "bad record MAC". A fresh TLS handshake per request costs
		// ~1 RTT but eliminates the entire class of stale-connection errors that
		// manifest as "failed to authenticate" in Claude Code.
		passthroughClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: newPassthroughTransport(newBootstrapResolver()),
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

	// 3. DLP — JSON-level redaction in decoded-string space.
	//
	//    Scanning and replacement both operate on decoded JSON string values,
	//    never on raw JSON bytes. This eliminates the class of bugs where a
	//    raw-bytes search finds a match inside base64 image data, JSON escape
	//    sequences, or other non-text fields, corrupting the forwarded body.
	//
	//    Detection (notifications, stats) is scoped to the LAST user message
	//    so previously-processed turns don't re-trigger alerts. Redaction is
	//    applied defensively to ALL user messages so a credential that appeared
	//    in an earlier turn is still scrubbed from the conversation history.
	//
	//    Fail-open: if the body cannot be parsed as JSON (e.g. a streaming
	//    chunk, a malformed request), it passes through unmodified.
	sessionOptedOut := h.confirm != nil && sessionKey != "" && h.confirm.IsOptedOut(sessionKey)
	vault := newLocalVault()
	st := h.applyDLPToJSON(body, sessionOptedOut, vault)

	// Block before forwarding if any finding has action="block".
	if st.blockKind != "" {
		h.logger.Warn("tlsinspect.dlp_blocked", log.Fields{
			"host": host,
			"kind": st.blockKind,
		})
		h.record(r, host, model, start, audit.VerdictBlockedDLP, []string{st.blockKind}, "")
		http.Error(w, `{"error":"content blocked by policy","reason":"dlp","kind":"`+st.blockKind+`"}`, http.StatusForbidden)
		return
	}

	// Notify on the first high-tier one-way redaction (Windows balloon tip).
	if st.notifyKind != "" && h.notifyFn != nil && sessionKey != "" {
		h.notifyFn(st.notifyKind, sessionKey)
	}

	newBody := st.newBody

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

	totalFindings := st.nOneWay + st.nTokenized + st.nAllowed + st.nSkipped
	fwdFields := log.Fields{
		"host":      host,
		"status":    resp.StatusCode,
		"in_bytes":  len(body),
		"out_bytes": len(newBody),
		"findings":  totalFindings,
	}
	if totalFindings > 0 {
		// Kind names and counts only — never plaintext content.
		fwdFields["kinds"] = summarizeKinds(st.kinds)
		fwdFields["redacted_one_way"] = st.nOneWay
		fwdFields["tokenized"] = st.nTokenized
		fwdFields["allowed"] = st.nAllowed
		if st.nSkipped > 0 {
			fwdFields["skipped_optout"] = st.nSkipped
		}
	}
	h.logger.Info("tlsinspect.forwarded", fwdFields)

	dlpKinds := make([]string, 0, len(st.kinds))
	for k := range st.kinds {
		dlpKinds = append(dlpKinds, k)
	}
	verdict := audit.VerdictFromError(nil, st.nOneWay+st.nTokenized > 0, false)
	h.record(r, host, model, start, verdict, dlpKinds, "")
}

// record appends a content-free audit entry for this request, if a recorder
// is configured. Never pass plaintext findings — only kind names, rule IDs,
// and the resolved verdict.
func (h *Handler) record(r *http.Request, host, model string, start time.Time, verdict audit.Verdict, dlpFindings []string, errMsg string) {
	if h.recorder == nil {
		return
	}
	h.recorder.Record(audit.Entry{
		Endpoint:    r.URL.Path,
		Mode:        "unary",
		Upstream:    host,
		Model:       model,
		Verdict:     verdict,
		DLPFindings: dlpFindings,
		DurationMS:  time.Since(start).Milliseconds(),
		Error:       errMsg,
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
	resp, err := h.passthroughClient.Do(req)
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

// dlpState is the result of one JSON-level DLP pass over a request body.
type dlpState struct {
	newBody    []byte         // redacted body (equals original if no changes)
	kinds      map[string]int // kind → count; kind names only, never plaintext
	nOneWay    int            // findings replaced with a static marker
	nTokenized int            // findings replaced with a vault pseudonym
	nAllowed   int            // findings flagged but not modified (allow/warn)
	nSkipped   int            // high-tier findings skipped due to session opt-out
	notifyKind string         // kind of the first high-tier one-way finding
	blockKind  string         // non-empty if any finding has action="block"
}

// applyDLPToJSON parses body as a JSON chat API request and applies DLP
// to every user-message text content field in decoded-string space.
//
// Key properties:
//   - Replacement happens on decoded Go strings, never on raw JSON bytes.
//     This prevents matches inside base64 image data or JSON escape sequences
//     from corrupting the forwarded body.
//   - Detection signals (notifications, stats) are scoped to the LAST user
//     message so prior turns cannot re-trigger alerts.
//   - Redaction is applied to ALL user messages for defense-in-depth.
//   - Fail-open: if the body cannot be parsed as a chat JSON, it is returned
//     unmodified and the zero dlpState is returned.
//   - Plaintext of any finding is NEVER written to logs or stored on disk.
func (h *Handler) applyDLPToJSON(body []byte, sessionOptedOut bool, vault *localVault) dlpState {
	st := dlpState{newBody: body, kinds: make(map[string]int)}

	// Parse the outer document preserving all non-messages fields verbatim.
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return st // not chat JSON — pass through
	}
	msgsRaw, ok := doc["messages"]
	if !ok {
		return st
	}
	var msgs []json.RawMessage
	if err := json.Unmarshal(msgsRaw, &msgs); err != nil {
		return st
	}

	// Locate the last user message (detection scope).
	lastUserIdx := -1
	for i := len(msgs) - 1; i >= 0; i-- {
		var probe struct {
			Role string `json:"role"`
		}
		if json.Unmarshal(msgs[i], &probe) == nil && probe.Role == "user" {
			lastUserIdx = i
			break
		}
	}
	if lastUserIdx < 0 {
		return st
	}

	// Process every user message. Only the last one contributes to stats.
	modified := false
	for i, msgRaw := range msgs {
		var msg struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		}
		if json.Unmarshal(msgRaw, &msg) != nil || msg.Role != "user" {
			continue
		}
		detect := (i == lastUserIdx)
		newContent, msgMod := h.redactContentField(msg.Content, detect, sessionOptedOut, vault, &st)
		if !msgMod {
			continue
		}
		// Splice modified content back preserving all other message fields.
		var msgMap map[string]json.RawMessage
		if json.Unmarshal(msgRaw, &msgMap) != nil {
			continue // fail-open for this message
		}
		msgMap["content"] = newContent
		newMsgRaw, err := json.Marshal(msgMap)
		if err != nil {
			continue
		}
		msgs[i] = newMsgRaw
		modified = true
	}

	if !modified {
		return st
	}

	newMsgsRaw, err := json.Marshal(msgs)
	if err != nil {
		st.newBody = body // fail-open
		return dlpState{newBody: body, kinds: make(map[string]int)}
	}
	doc["messages"] = newMsgsRaw
	newBody, err := json.Marshal(doc)
	if err != nil {
		return dlpState{newBody: body, kinds: make(map[string]int)} // fail-open
	}
	st.newBody = newBody
	return st
}

// redactContentField handles the "content" field of a user message.
// Content is either a plain string or an array of typed content blocks.
// Only "text" blocks are scanned; image/tool blocks are left untouched.
func (h *Handler) redactContentField(contentRaw json.RawMessage, detect, sessionOptedOut bool, vault *localVault, st *dlpState) (json.RawMessage, bool) {
	// Plain-string content.
	var s string
	if json.Unmarshal(contentRaw, &s) == nil {
		newS, mod := h.redactDecodedText(s, detect, sessionOptedOut, vault, st)
		if !mod {
			return contentRaw, false
		}
		b, _ := json.Marshal(newS)
		return b, true
	}

	// Array of typed content blocks (multi-modal / tool content).
	var blocks []json.RawMessage
	if json.Unmarshal(contentRaw, &blocks) != nil {
		return contentRaw, false // unknown shape — fail-open
	}
	modifiedAny := false
	for i, blkRaw := range blocks {
		var blk map[string]json.RawMessage
		if json.Unmarshal(blkRaw, &blk) != nil {
			continue
		}
		var typ string
		if json.Unmarshal(blk["type"], &typ) != nil || typ != "text" {
			continue // skip image, tool_use, tool_result, document, etc.
		}
		var text string
		if json.Unmarshal(blk["text"], &text) != nil {
			continue
		}
		newText, mod := h.redactDecodedText(text, detect, sessionOptedOut, vault, st)
		if !mod {
			continue
		}
		blk["text"], _ = json.Marshal(newText)
		blocks[i], _ = json.Marshal(blk)
		modifiedAny = true
	}
	if !modifiedAny {
		return contentRaw, false
	}
	b, err := json.Marshal(blocks)
	if err != nil {
		return contentRaw, false
	}
	return b, true
}

// redactDecodedText applies DLP patterns to a decoded Go string and
// returns the redacted string. Replacement is done entirely in decoded-
// string space — no JSON bytes are involved, so encoding mismatches
// are impossible. Plaintext of matched values is never stored or logged.
func (h *Handler) redactDecodedText(text string, detect, sessionOptedOut bool, vault *localVault, st *dlpState) (string, bool) {
	// Run pattern-based DLP followed by intent-based password detection.
	scanned := patterns.Scan(text)
	for _, r := range intent.FindPasswordCandidates(text) {
		scanned = append(scanned, patterns.Finding{
			Kind:  api.PIIPassword,
			Start: r[0],
			End:   r[1],
			Text:  text[r[0]:r[1]],
		})
	}
	if len(scanned) == 0 {
		return text, false
	}

	// Build replacement pairs in decoded-string space.
	pairs := make([]string, 0, len(scanned)*2)
	for _, f := range scanned {
		if detect {
			st.kinds[string(f.Kind)]++
		}
		action := h.resolveAction(string(f.Kind))

		if sessionOptedOut && api.TierForKind(f.Kind) == api.TierHigh {
			if detect {
				st.nSkipped++
			}
			continue
		}

		switch action {
		case "redact", "warn":
			pseudo := vault.tokenize(string(f.Kind), f.Text)
			pairs = append(pairs, f.Text, pseudo)
			if detect {
				st.nTokenized++
			}
		case "redact_one_way":
			marker := partialMaskOrStaticMarker(f)
			pairs = append(pairs, f.Text, marker)
			if detect {
				st.nOneWay++
				if st.notifyKind == "" {
					st.notifyKind = string(f.Kind)
				}
			}
		case "block":
			if detect && st.blockKind == "" {
				st.blockKind = string(f.Kind)
			}
		default: // "allow" / "" — flag on dashboard, never modify body
			if detect {
				st.nAllowed++
			}
		}
	}

	if len(pairs) == 0 {
		return text, false
	}
	// Apply all replacements in a single pass on the DECODED string.
	return strings.NewReplacer(pairs...).Replace(text), true
}

// partialMaskOrStaticMarker returns the replacement for a finding.
// Credit cards and SSNs get their last 6 digits masked (keeps context
// visible so Claude can still help). All other high-tier kinds are
// fully replaced with a static marker.
func partialMaskOrStaticMarker(f patterns.Finding) string {
	switch f.Kind {
	case api.PIICreditCard:
		return maskLastNDigits(f.Text, 6) // 4111 1111 11** ****
	case api.PIISSN:
		return maskLastNDigits(f.Text, 6) // 123-**-****
	}
	return api.StaticMarkerForKind(f.Kind)
}

// maskLastNDigits replaces the last n digit characters in s with '*',
// preserving any non-digit separators (spaces, dashes, dots).
// Example: maskLastNDigits("4111-1111-1111-1111", 6) → "4111-1111-11**-****"
func maskLastNDigits(s string, n int) string {
	runes := []rune(s)
	masked := 0
	for i := len(runes) - 1; i >= 0 && masked < n; i-- {
		if runes[i] >= '0' && runes[i] <= '9' {
			runes[i] = '*'
			masked++
		}
	}
	return string(runes)
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

// ProbeConnectivity makes a lightweight HEAD request to the Anthropic API
// through the passthrough client (same transport used for non-chat endpoints)
// and reports whether the upstream is reachable. A 4xx from Anthropic still
// counts as reachable — it means TLS and routing work but auth is absent,
// which is expected for an unauthenticated probe. Only a network error or
// timeout means cloakline is blocking traffic.
func (h *Handler) ProbeConnectivity(ctx context.Context) (latencyMS int64, err error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://api.anthropic.com", nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "cloakline-probe/1.0")

	start := time.Now()
	resp, err := h.passthroughClient.Do(req)
	latencyMS = time.Since(start).Milliseconds()
	if err != nil {
		return latencyMS, fmt.Errorf("upstream unreachable: %w", err)
	}
	resp.Body.Close()
	// Any HTTP response (even 401/403) means the proxy chain works.
	return latencyMS, nil
}
