// Package log is the redacting structured logger.
//
// Emits JSON lines to stdout. Never accepts %v-style formatting — the only
// entry points take typed key/value pairs, so a caller cannot accidentally
// spill a whole request struct into the log.
//
// See docs/threat-model.md T3 for the threats this defends against.
package log

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Level is a log level. String levels are used on the wire.
type Level uint8

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	}
	return "unknown"
}

// Logger is the log entry point. Safe for concurrent use.
type Logger struct {
	mu       sync.Mutex
	out      io.Writer
	minLevel Level
	base     Fields
}

// Fields is the typed key/value bag. All values are one of: string, int,
// int64, float64, bool, time.Time, or Fields (nested).
type Fields map[string]any

// New returns a logger at the given minimum level, writing to stdout.
func New(min Level) *Logger {
	return &Logger{out: os.Stdout, minLevel: min}
}

// NewWithWriter is the test constructor.
func NewWithWriter(w io.Writer, min Level) *Logger {
	return &Logger{out: w, minLevel: min}
}

// With returns a child logger with additional base fields.
func (l *Logger) With(f Fields) *Logger {
	merged := make(Fields, len(l.base)+len(f))
	for k, v := range l.base {
		merged[k] = v
	}
	for k, v := range f {
		merged[k] = v
	}
	return &Logger{out: l.out, minLevel: l.minLevel, base: merged}
}

func (l *Logger) Debug(msg string, f Fields) { l.emit(LevelDebug, msg, f) }
func (l *Logger) Info(msg string, f Fields)  { l.emit(LevelInfo, msg, f) }
func (l *Logger) Warn(msg string, f Fields)  { l.emit(LevelWarn, msg, f) }
func (l *Logger) Error(msg string, f Fields) { l.emit(LevelError, msg, f) }

// DebugCtx / InfoCtx / etc. accept a context so request IDs can attach.
func (l *Logger) InfoCtx(ctx context.Context, msg string, f Fields) {
	l.emit(LevelInfo, msg, mergeCtx(ctx, f))
}
func (l *Logger) WarnCtx(ctx context.Context, msg string, f Fields) {
	l.emit(LevelWarn, msg, mergeCtx(ctx, f))
}
func (l *Logger) ErrorCtx(ctx context.Context, msg string, f Fields) {
	l.emit(LevelError, msg, mergeCtx(ctx, f))
}
func (l *Logger) DebugCtx(ctx context.Context, msg string, f Fields) {
	l.emit(LevelDebug, msg, mergeCtx(ctx, f))
}

type ctxKey int

const (
	requestIDKey ctxKey = 1
	endpointKey  ctxKey = 2
)

// WithRequestID attaches a request ID to a context so loggers auto-emit it.
func WithRequestID(parent context.Context, id string) context.Context {
	return context.WithValue(parent, requestIDKey, id)
}

// WithEndpoint attaches the ingress endpoint (e.g. "/v1/chat/completions")
// so downstream components (audit recorder) can identify it.
func WithEndpoint(parent context.Context, ep string) context.Context {
	return context.WithValue(parent, endpointKey, ep)
}

// EndpointFrom retrieves the ingress endpoint from context, "" if unset.
func EndpointFrom(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(endpointKey).(string)
	return v
}

func mergeCtx(ctx context.Context, f Fields) Fields {
	if ctx == nil {
		return f
	}
	if v := ctx.Value(requestIDKey); v != nil {
		if f == nil {
			f = Fields{}
		}
		if _, exists := f["request_id"]; !exists {
			f["request_id"] = v
		}
	}
	return f
}

func (l *Logger) emit(lvl Level, msg string, f Fields) {
	if lvl < l.minLevel {
		return
	}
	rec := make(Fields, 4+len(l.base)+len(f))
	rec["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	rec["level"] = lvl.String()
	rec["msg"] = sanitize(msg)
	for k, v := range l.base {
		rec[k] = redactValue(k, v)
	}
	for k, v := range f {
		rec[k] = redactValue(k, v)
	}
	buf, err := json.Marshal(rec)
	if err != nil {
		buf = []byte(fmt.Sprintf(`{"ts":%q,"level":"error","msg":"log_marshal_failed","err":%q}`,
			time.Now().UTC().Format(time.RFC3339Nano), err.Error()))
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.out.Write(buf)
	_, _ = l.out.Write([]byte("\n"))
}

// -------- Redaction --------

var (
	// Sensitive key names — case-insensitive substring match.
	sensitiveKeys = []string{
		"authorization", "cookie", "set-cookie",
		"api_key", "apikey", "api-key",
		"secret", "token", "password", "passwd",
		"x-api-key", "openai-api-key", "anthropic-api-key",
	}

	// Newline and other control characters that could enable log-injection.
	// Intentionally includes 0x09 (tab), 0x0a (LF), 0x0d (CR) — allowing any
	// of those to reach the log line breaks JSON parsing and enables
	// log-injection where user input becomes a fake log record.
	ctrlRe = regexp.MustCompile(`[\x00-\x1f\x7f]`)
)

// redactValue applies field-level redaction based on the field name.
func redactValue(key string, v any) any {
	lk := strings.ToLower(key)
	for _, s := range sensitiveKeys {
		if strings.Contains(lk, s) {
			return redactSecret(v)
		}
	}
	// If the value is a Fields, recurse.
	if inner, ok := v.(Fields); ok {
		out := make(Fields, len(inner))
		for k, x := range inner {
			out[k] = redactValue(k, x)
		}
		return out
	}
	if s, ok := v.(string); ok {
		return sanitize(s)
	}
	return v
}

// redactSecret returns a length + short prefix hash instead of the plaintext.
func redactSecret(v any) string {
	s, ok := v.(string)
	if !ok {
		return "<redacted>"
	}
	if s == "" {
		return "<empty>"
	}
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("<redacted len=%d sha256-first-8=%s>",
		len(s), hex.EncodeToString(h[:4]))
}

// sanitize strips control characters and rewrites anything that looks like
// an API key (any provider — sk-*, sk-ant-*, sk-fake-*, xoxb-, AKIA-, ghp_,
// github_pat_) into a redacted placeholder. Defense-in-depth against
// providers that echo the caller's key inside error responses.
func sanitize(s string) string {
	if len(s) > 1024 {
		s = s[:1024] + "…"
	}
	s = ctrlRe.ReplaceAllString(s, " ")
	s = secretInStringRe.ReplaceAllString(s, "<redacted-secret>")
	return s
}

var secretInStringRe = regexp.MustCompile(
	`sk-[A-Za-z0-9_-]{6,}|AKIA[0-9A-Z]{16}|(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}|xox[bpars]-[A-Za-z0-9-]{10,}`,
)

// RedactBody produces a body-safe reference: length and content hash only.
func RedactBody(body []byte) string {
	h := sha256.Sum256(body)
	return fmt.Sprintf("<len=%d sha256=%s>", len(body), hex.EncodeToString(h[:]))
}
