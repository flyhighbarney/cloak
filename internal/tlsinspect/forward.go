package tlsinspect

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"policyd/internal/api"
	"policyd/internal/dlp/patterns"
	"policyd/internal/obs/log"
	"policyd/internal/stage/injection"
)

// Handler applies the inspection pipeline to a single request/response.
//
// Flow:
//   1. Read the request body into memory (up to MaxBodyBytes).
//   2. Extract prompt text from the JSON body (Anthropic + OpenAI shapes).
//   3. Run the injection rule set. High-score → 403 to client, no forward.
//   4. Run DLP patterns. Block hits (api_key/aws_key/etc) → 403.
//      Redact hits (SSN, credit card, email) → replaced with pseudonyms
//      inside the request body. Local per-request map remembers the
//      originals so we can restore on the return path.
//   5. Forward the modified body to the real host with the ORIGINAL
//      auth headers untouched.
//   6. On response, walk the body and swap pseudonyms back to originals
//      so the CLI sees its real values.
type Handler struct {
	logger        *log.Logger
	meter         MeterFacade
	forwardClient *http.Client
	maxBodyBytes  int64

	dlpActions dlpActionResolver // per-kind action policy
	injRules   []injection.Rule
	injScore   int // threshold; sum > threshold → block
}

// MeterFacade is the subset of the meter interface this handler needs.
// Kept as a facade so tests can plug in a no-op meter.
type MeterFacade interface {
	Counter(name api.MetricName, dims map[api.DimKey]string)
}

// dlpActionResolver maps a finding kind to an action.
type dlpActionResolver interface {
	Action(kind string) string // "allow" | "warn" | "redact" | "block"
}

// HandlerConfig is the constructor input.
type HandlerConfig struct {
	Logger        *log.Logger
	Meter         MeterFacade
	MaxBodyBytes  int64
	DLPActions    dlpActionResolver
	InjectionRules []injection.Rule
	InjectionThreshold int
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
	return &Handler{
		logger:       c.Logger,
		meter:        c.Meter,
		maxBodyBytes: c.MaxBodyBytes,
		dlpActions:   c.DLPActions,
		injRules:     c.InjectionRules,
		injScore:     c.InjectionThreshold,
		forwardClient: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

// Handle is the ServeHTTP body split out from server.go for readability.
func (h *Handler) Handle(w http.ResponseWriter, r *http.Request, host string) {
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

	// 2. Extract prompt text and inspect.
	pieces := extractPromptText(body)
	joined := strings.Join(pieces, "\n")

	// 3. Injection score.
	if joined != "" {
		result := injection.Score(joined, h.injRules)
		if result.Score >= h.injScore {
			h.logger.Warn("tlsinspect.injection_blocked", log.Fields{
				"host":  host,
				"score": result.Score,
			})
			http.Error(w, `{"error":"content blocked by policy","reason":"injection"}`, http.StatusForbidden)
			return
		}
	}

	// 4. DLP.
	scanned := patterns.Scan(joined)
	if len(scanned) > 0 {
		for _, f := range scanned {
			act := h.dlpActions.Action(string(f.Kind))
			if act == "block" {
				h.logger.Warn("tlsinspect.dlp_blocked", log.Fields{
					"host": host,
					"kind": string(f.Kind),
				})
				http.Error(w, `{"error":"content blocked by policy","reason":"dlp","kind":"`+string(f.Kind)+`"}`, http.StatusForbidden)
				return
			}
		}
	}

	// 5. Tokenize redact-mode findings. Local map remembers originals so
	//    the response can restore them for the client.
	vault := newLocalVault()
	newBody := body
	for _, f := range scanned {
		act := h.dlpActions.Action(string(f.Kind))
		if act != "redact" && act != "warn" {
			continue
		}
		pseudo := vault.tokenize(string(f.Kind), f.Text)
		newBody = bytes.ReplaceAll(newBody, []byte(f.Text), []byte(pseudo))
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
		h.logger.Warn("tlsinspect.forward_failed", log.Fields{"host": host, "err": err.Error()})
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

	h.logger.Info("tlsinspect.forwarded", log.Fields{
		"host":        host,
		"status":      resp.StatusCode,
		"in_bytes":    len(body),
		"out_bytes":   len(newBody),
		"findings":    len(scanned),
	})
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
