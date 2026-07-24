// Command policyctl is the developer CLI for policyd.
//
// It has two modes:
//   1. Standalone: `policyctl scan` runs DLP patterns against a file or
//      stdin without any gateway. Use before pasting code into ChatGPT.
//   2. Client: `policyctl chat`, `doctor`, `keys`, `tail` talk to a running
//      policyd. Configured via `~/.config/policyctl/config.yaml`.
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
	case "version", "--version", "-v":
		fmt.Printf("policyctl %s\n", Version)
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
	fmt.Print(`policyctl — AI safety at your fingertips.

USAGE
    policyctl <command> [options]

COMMANDS
    scan        Scan a file or stdin for PII, secrets, and API keys.
                Runs offline — no gateway needed.

                    policyctl scan file.py
                    cat contract.txt | policyctl scan -
                    policyctl scan --json file.py

    chat        Send a prompt through your gateway and print the reply.

                    policyctl chat "summarize this contract"
                    policyctl chat --model gpt-4o-mini "hello"

    doctor      Validate local config, ping the gateway, verify the key.

                    policyctl doctor

    login       Save gateway URL + virtual key to ~/.config/policyctl/config.yaml.

                    policyctl login https://gateway.example.com

    keys        Manage tenant virtual keys (requires gateway admin endpoint).

                    policyctl keys list          (coming soon)
                    policyctl keys create ...    (coming soon)

    tail        Live-stream recent audit events from the gateway.
                (coming soon — for now open /admin in your browser)

    version     Print CLI version.

CONFIG
    ~/.config/policyctl/config.yaml holds:
        gateway: https://gateway.example.com
        api_key: sk-gw-...
        tenant:  acme

    Override at run time with env vars:
        POLICYD_GATEWAY, POLICYD_API_KEY.

`)
}
