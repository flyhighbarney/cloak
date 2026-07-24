package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
)

// cmdLogin saves gateway URL + virtual key to ~/.config/policyctl/config.yaml.
// It intentionally does NOT verify the key — that's what `doctor` is for —
// so the login command works offline too.
func cmdLogin(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: policyctl login <gateway-url>")
	}
	gateway := strings.TrimRight(args[0], "/")
	if !strings.HasPrefix(gateway, "http://") && !strings.HasPrefix(gateway, "https://") {
		gateway = "https://" + gateway
	}
	fmt.Printf("gateway: %s\n", cyan(gateway))
	fmt.Print("virtual key (sk-gw-…): ")
	reader := bufio.NewReader(os.Stdin)
	key, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	key = strings.TrimSpace(key)
	if !strings.HasPrefix(key, "sk-gw-") {
		return fmt.Errorf("virtual keys must start with sk-gw-")
	}
	fmt.Print("tenant (optional): ")
	tenant, _ := reader.ReadString('\n')
	tenant = strings.TrimSpace(tenant)

	cfg := &clientConfig{Gateway: gateway, APIKey: key, Tenant: tenant}
	if err := saveConfig(cfg); err != nil {
		return err
	}
	path, _ := configPath()
	fmt.Printf("%s saved to %s\n", green("✓"), gray(path))
	fmt.Printf("run %s to verify.\n", cyan("policyctl doctor"))
	return nil
}
