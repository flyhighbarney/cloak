// Command cloak is the developer CLI for cloakline.
//
// It has two modes:
//  1. Standalone: `cloak scan` runs DLP patterns against a file or
//     stdin without any gateway. Use before pasting code into ChatGPT.
//  2. Client: `cloak chat`, `doctor`, `keys`, `tail`, `dashboard` talk
//     to a running cloakline daemon.
package main

import (
	"fmt"
	"os"
)

const Version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "setup", "install":
		err = cmdSetup(args)
	case "scan":
		err = cmdScan(args)
	case "chat":
		err = cmdChat(args)
	case "doctor":
		err = cmdDoctor(args)
	case "login":
		err = cmdLogin(args)
	case "keys":
		err = cmdKeys(args)
	case "tail":
		err = cmdTail(args)
	case "dashboard", "dash":
		err = cmdDashboard(args)
	case "trust":
		err = cmdTrust(args)
	case "launch":
		err = cmdLaunch(args)
	case "version", "--version", "-v":
		fmt.Printf("cloak %s\n", Version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(`cloak — AI safety at your fingertips.

USAGE
    cloak <command> [options]

COMMANDS
    setup       One-time interactive setup. Installs the CA, saves your
                Anthropic + OpenAI keys to the OS keyring, enables the
                transparent scanner, and (optionally) starts cloakline on
                login. After this, use claude, codex, or Cursor normally —
                no wrapper needed.  Also accepts: cloak install

                    cloak setup

    scan        Scan a file or stdin for PII, secrets, and API keys.
                Runs offline — no gateway needed.

                    cloak scan file.py
                    cat contract.txt | cloak scan -
                    cloak scan --json file.py

    chat        Send a prompt through your gateway and print the reply.

                    cloak chat "summarize this contract"
                    cloak chat --model gpt-4o-mini "hello"

    doctor      Validate local config, ping the gateway, verify the key.

                    cloak doctor

    login       Save gateway URL + virtual key to ~/.config/cloak/config.yaml.

                    cloak login https://gateway.example.com

    keys        Manage tenant virtual keys (requires gateway admin endpoint).

                    cloak keys list          (coming soon)
                    cloak keys create ...    (coming soon)

    tail        Live terminal dashboard — streaming stats and recent audit
                events from the local cloakline daemon.

                    cloak tail

    dashboard   Open the admin web dashboard in your default browser.

                    cloak dashboard

    trust       Manage the local inspection CA (used by the TLS inspection
                module for transparent scanning of AI CLI traffic).

                    cloak trust show      # print path + install cmd
                    cloak trust install   # add to OS trust store
                    cloak trust status    # is the CA trusted?
                    cloak trust remove    # revoke and delete

    launch      Run a developer CLI through cloakline's scanner. Preflights
                cloakline health + CA trust, then execs the target with
                the correct API key from the dashboard vault.

                    cloak launch claude -p "hello"
                    cloak launch codex "print hi"
                    cloak launch cursor        # print BYOK setup block

    version     Print CLI version.

CONFIG
    ~/.config/cloak/config.yaml holds:
        gateway: https://gateway.example.com
        api_key: sk-gw-...
        tenant:  acme

    Override at run time with env vars:
        POLICYD_GATEWAY, POLICYD_API_KEY.

`)
}
