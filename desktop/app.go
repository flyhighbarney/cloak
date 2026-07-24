package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// App is the Wails-bound backend. Every method with a capitalized name is
// callable from the JavaScript frontend via `window.go.main.App.<Method>()`.
type App struct {
	ctx    context.Context
	mu     sync.Mutex
	cfg    clientConfig
	client *http.Client
}

type clientConfig struct {
	Gateway string `yaml:"gateway"`
	APIKey  string `yaml:"api_key"`
	Tenant  string `yaml:"tenant,omitempty"`
}

func NewApp() *App {
	return &App{
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.mu.Lock()
	defer a.mu.Unlock()
	if path, err := configPath(); err == nil {
		if data, rerr := os.ReadFile(path); rerr == nil {
			_ = yaml.Unmarshal(data, &a.cfg)
		}
	}
	if v := os.Getenv("POLICYD_GATEWAY"); v != "" {
		a.cfg.Gateway = v
	}
	if v := os.Getenv("POLICYD_API_KEY"); v != "" {
		a.cfg.APIKey = v
	}
}

// -------- Frontend-bound methods --------

// GetConfig returns the current gateway URL + a masked key so the UI can
// display "connected to X" without leaking the key.
func (a *App) GetConfig() map[string]string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return map[string]string{
		"gateway": a.cfg.Gateway,
		"key":     maskKey(a.cfg.APIKey),
		"tenant":  a.cfg.Tenant,
	}
}

// SaveConfig persists the gateway URL and key to
// ~/.config/policyctl/config.yaml (shared with the CLI).
func (a *App) SaveConfig(gateway, apiKey, tenant string) string {
	if !strings.HasPrefix(apiKey, "sk-gw-") {
		return "error: virtual key must start with sk-gw-"
	}
	gateway = strings.TrimRight(gateway, "/")
	if !strings.HasPrefix(gateway, "http://") && !strings.HasPrefix(gateway, "https://") {
		gateway = "https://" + gateway
	}
	a.mu.Lock()
	a.cfg = clientConfig{Gateway: gateway, APIKey: apiKey, Tenant: tenant}
	a.mu.Unlock()

	path, err := configPath()
	if err != nil {
		return "error: " + err.Error()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "error: " + err.Error()
	}
	data, err := yaml.Marshal(a.cfg)
	if err != nil {
		return "error: " + err.Error()
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "error: " + err.Error()
	}
	return "ok"
}

// PreviewRedaction is a local scan of the composed prompt. Uses the built-in
// regex set so the user sees what WILL be redacted before they hit Send.
// No gateway call is made.
func (a *App) PreviewRedaction(text string) []map[string]any {
	findings := scan(text)
	out := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		out = append(out, map[string]any{
			"kind":  f.Kind,
			"start": f.Start,
			"end":   f.End,
			"text":  maskFinding(f.Text),
		})
	}
	return out
}

// SendPrompt routes the prompt through the configured gateway using the
// OpenAI-compatible /v1/chat/completions endpoint. Returns the model's
// reply as a string.
func (a *App) SendPrompt(model, prompt string) map[string]any {
	a.mu.Lock()
	cfg := a.cfg
	a.mu.Unlock()

	if cfg.Gateway == "" || cfg.APIKey == "" {
		return map[string]any{"error": "gateway not configured"}
	}
	if model == "" {
		model = "gpt-4o-mini"
	}
	body := map[string]any{
		"model": model,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}
	buf, _ := json.Marshal(body)
	url := strings.TrimRight(cfg.Gateway, "/") + "/v1/chat/completions"
	req, err := http.NewRequestWithContext(a.ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 400 {
		return map[string]any{
			"error":  fmt.Sprintf("gateway returned %d", resp.StatusCode),
			"detail": string(respBytes),
		}
	}
	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(respBytes, &parsed); err != nil {
		return map[string]any{"error": "decode: " + err.Error()}
	}
	if len(parsed.Choices) == 0 {
		return map[string]any{"error": "empty response"}
	}
	return map[string]any{"reply": parsed.Choices[0].Message.Content}
}

// HealthCheck probes the gateway's /healthz. Used to render the connection
// status pill in the header.
func (a *App) HealthCheck() bool {
	a.mu.Lock()
	url := strings.TrimRight(a.cfg.Gateway, "/") + "/healthz"
	a.mu.Unlock()
	if url == "/healthz" {
		return false
	}
	ctx, cancel := context.WithTimeout(a.ctx, 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := a.client.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == 200
}

// -------- helpers --------

func configPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "policyctl", "config.yaml"), nil
}

func maskKey(k string) string {
	if len(k) <= 10 {
		return ""
	}
	return k[:8] + strings.Repeat("*", 8) + k[len(k)-4:]
}

func maskFinding(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:3] + strings.Repeat("*", len(s)-6) + s[len(s)-3:]
}
