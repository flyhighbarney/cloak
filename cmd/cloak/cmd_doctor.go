package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

// cmdDoctor validates the local config and probes the gateway. This is the
// first command a dev runs when something looks off. Every check either
// prints ✓ or emits an actionable fix.
func cmdDoctor(_ []string) error {
	fmt.Println(bold("cloak doctor"))
	fmt.Println(gray(strings.Repeat("─", 40)))

	cfg, err := loadConfig()
	if err != nil {
		fmt.Printf("  %s config: %v\n", red("✗"), err)
		return err
	}

	// 1. Config file readable?
	path, _ := configPath()
	if _, err := os.Stat(path); err == nil {
		fmt.Printf("  %s config file: %s\n", green("✓"), gray(path))
	} else {
		fmt.Printf("  %s config file missing (%s)\n", yellow("!"), gray(path))
		fmt.Printf("      run: %s\n", cyan("cloak login <gateway-url>"))
	}

	// 2. Gateway URL well-formed?
	u, uerr := url.Parse(cfg.Gateway)
	if uerr != nil || u.Scheme == "" {
		fmt.Printf("  %s gateway URL malformed: %s\n", red("✗"), cfg.Gateway)
		return fmt.Errorf("gateway URL")
	}
	if u.Scheme != "https" && !strings.Contains(u.Host, "localhost") && !strings.Contains(u.Host, "127.0.0.1") {
		fmt.Printf("  %s gateway URL uses http:// on a non-local host — traffic is unencrypted\n", yellow("!"))
	} else {
		fmt.Printf("  %s gateway URL: %s\n", green("✓"), cfg.Gateway)
	}

	// 3. Virtual key format?
	if !strings.HasPrefix(cfg.APIKey, "sk-gw-") {
		fmt.Printf("  %s api_key does not start with sk-gw-\n", red("✗"))
	} else {
		fmt.Printf("  %s api_key: %s\n", green("✓"), maskKey(cfg.APIKey))
	}

	// 4. Reach /healthz?
	client := newClient(cfg)
	var health struct {
		Status string `json:"status"`
	}
	if err := client.getJSON("/healthz", &health); err != nil {
		fmt.Printf("  %s gateway unreachable: %v\n", red("✗"), err)
		return err
	}
	fmt.Printf("  %s gateway healthy (status: %s)\n", green("✓"), health.Status)

	// 5. Auth by making a trivial chat call.
	fmt.Printf("  %s testing auth with a 1-token completion...\n", cyan("…"))
	type msg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	type req struct {
		Model     string `json:"model"`
		Messages  []msg  `json:"messages"`
		MaxTokens int    `json:"max_tokens,omitempty"`
	}
	body := req{
		Model:     "gpt-4o-mini",
		Messages:  []msg{{Role: "user", Content: "hi"}},
		MaxTokens: 1,
	}
	if err := client.postJSON("/v1/chat/completions", body, nil); err != nil {
		fmt.Printf("  %s auth or upstream failed: %v\n", red("✗"), err)
		return err
	}
	fmt.Printf("  %s auth and upstream OK\n\n", green("✓"))
	fmt.Println(bold("all checks passed."))
	return nil
}

func maskKey(k string) string {
	if len(k) <= 10 {
		return "sk-gw-***"
	}
	return k[:8] + strings.Repeat("*", len(k)-12) + k[len(k)-4:]
}
