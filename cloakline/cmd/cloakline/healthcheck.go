package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

// runHealthcheck probes the local admin /healthz endpoint. Meant to be
// invoked by Docker's healthcheck against a distroless container that has
// no shell, no curl, and no wget.
//
// The admin listen address is read from an env var so we don't have to
// parse the YAML config just to probe. Compose passes:
//     ADMIN_HEALTHCHECK_ADDR=127.0.0.1:4001
// If unset, defaults to 127.0.0.1:4001.
func runHealthcheck() error {
	addr := os.Getenv("ADMIN_HEALTHCHECK_ADDR")
	if addr == "" {
		addr = "127.0.0.1:4001"
	}
	// Prefer a resolved localhost dial so we don't depend on DNS.
	if host, _, err := net.SplitHostPort(addr); err == nil && host == "" {
		addr = "127.0.0.1" + addr
	}
	client := &http.Client{Timeout: 2 * time.Second}
	url := "http://" + addr + "/healthz"
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("healthcheck GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck: %s returned %d", url, resp.StatusCode)
	}
	return nil
}
