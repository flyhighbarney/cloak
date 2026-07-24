package main

import "fmt"

// cmdKeys is a placeholder — the gateway tenant-key management API
// hasn't landed yet. It prints a friendly notice with manual instructions.

func cmdKeys(_ []string) error {
	fmt.Printf(`%s keys management is coming soon.

For now, add tenants by editing %s and restarting cloakline:

    - key: sk-gw-<name>-<random>
      tenant_id: <name>
      key_id: <name>-prod
      scopes: [chat:read, chat:stream]
      budget_ref: default
      routing_policy: openai-default-v1
      expiry_unix: 0

Or manage API keys for providers via the dashboard:
    %s

`, yellow("!"),
		cyan("configs/principals.yaml"),
		cyan(adminURL+"/keys"))
	return nil
}
