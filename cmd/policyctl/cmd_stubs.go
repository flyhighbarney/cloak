package main

import "fmt"

// cmdKeys and cmdTail are placeholders — the gateway admin API endpoints
// they will call haven't landed yet. They print a friendly notice so the
// user knows the surface is planned, not broken.

func cmdKeys(_ []string) error {
	fmt.Printf(`%s keys management is coming soon.

For now, add tenants by editing %s and restarting the gateway:

    - key: sk-gw-<name>-<random>
      tenant_id: <name>
      key_id: <name>-prod
      scopes: [chat:read, chat:stream]
      budget_ref: default
      routing_policy: openai-default-v1
      expiry_unix: 0

Then: %s

`, yellow("!"),
		cyan("configs/principals.yaml"),
		cyan("./deploy/deploy.sh"))
	return nil
}

func cmdTail(_ []string) error {
	cfg, err := loadConfig()
	if err == nil {
		fmt.Printf(`%s live audit tail is coming soon.

For now, view recent requests at:

    %s

Basic auth: username %s + the ADMIN_PASSWORD you set in deploy/.env.

`, yellow("!"),
			cyan(cfg.Gateway+"/admin"),
			cyan("admin"))
		return nil
	}
	fmt.Printf(`%s live audit tail is coming soon.

For now, view recent requests at your gateway's %s endpoint.
`, yellow("!"), cyan("/admin"))
	return nil
}
