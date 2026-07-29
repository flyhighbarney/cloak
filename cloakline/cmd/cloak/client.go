package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// httpClient wraps the CLI's HTTP client with the loaded config.
type httpClient struct {
	cfg    *clientConfig
	client *http.Client
}

func newClient(cfg *clientConfig) *httpClient {
	return &httpClient{
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// gatewayURL joins the configured gateway base URL with the given path.
func (c *httpClient) gatewayURL(path string) string {
	base := strings.TrimRight(c.cfg.Gateway, "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path
}

// getJSON performs a GET and decodes the JSON body.
func (c *httpClient) getJSON(path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, c.gatewayURL(path), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("GET %s: %d %s", path, resp.StatusCode, string(buf))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// postJSON POSTs a JSON body and decodes the JSON response.
func (c *httpClient) postJSON(path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, c.gatewayURL(path), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("POST %s: %d — %s", path, resp.StatusCode, string(buf))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
