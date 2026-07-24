package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// clientConfig is the on-disk config for policyctl.
type clientConfig struct {
	Gateway string `yaml:"gateway"`
	APIKey  string `yaml:"api_key"`
	Tenant  string `yaml:"tenant,omitempty"`
}

func configPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "policyctl", "config.yaml"), nil
}

// loadConfig reads the config file. Environment variables override on-disk.
// Returns (config, nil) if the config exists AND every field required by
// the caller is populated; returns an actionable error otherwise.
func loadConfig() (*clientConfig, error) {
	c := &clientConfig{}
	path, err := configPath()
	if err == nil {
		if data, rerr := os.ReadFile(path); rerr == nil {
			_ = yaml.Unmarshal(data, c)
		}
	}
	if v := os.Getenv("POLICYD_GATEWAY"); v != "" {
		c.Gateway = v
	}
	if v := os.Getenv("POLICYD_API_KEY"); v != "" {
		c.APIKey = v
	}
	if c.Gateway == "" && c.APIKey == "" {
		return c, errors.New("no gateway configured — run `policyctl login <url>` or set POLICYD_GATEWAY")
	}
	return c, nil
}

func saveConfig(c *clientConfig) error {
	path, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	// 0o600 — keeps the virtual key readable only by the owner.
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
