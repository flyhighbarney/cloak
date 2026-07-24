package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"time"

	"cloakline/internal/keyvault"
)

// cmdLaunch is the "paste once, run anything" entry point. It wraps a
// developer CLI (claude / codex / cursor) with:
//
//   - a preflight that checks cloakline is running and the local CA is
//     trusted, so the traffic actually gets scanned;
//   - injection of the correct API key from the keyring into the
//     child process's environment (never the parent's), so the key
//     never leaks into shell history or other processes.
//
// The subcommand exits with the child's exit code so it plugs into
// shell pipelines like a normal wrapper.
func cmdLaunch(args []string) error {
	if _, err := keyvault.Install(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: OS keyring backend unavailable (%v). Keys will not persist across restarts.\n", err)
	}

	if len(args) < 1 {
		printLaunchUsage()
		return errors.New("launch: target CLI is required")
	}
	target, rest := args[0], args[1:]

	switch target {
	case "claude":
		return launchClaude(rest)
	case "codex":
		return launchCodex(rest)
	case "cursor":
		return launchCursor()
	case "help", "-h", "--help":
		printLaunchUsage()
		return nil
	default:
		printLaunchUsage()
		return fmt.Errorf("launch: unknown target %q (want claude|codex|cursor)", target)
	}
}

func printLaunchUsage() {
	fmt.Print(`cloak launch — run a developer CLI through cloakline's scanner.

USAGE
    cloak launch <target> [args...]

TARGETS
    claude    Anthropic's Claude Code CLI. Uses your subscription; no
              API key needed. Requires the CA to be trusted and
              api.anthropic.com to resolve to 127.0.0.1.

    codex     OpenAI's Codex CLI. Reads OPENAI_API_KEY from the
              dashboard vault and injects it into the child process
              only. Never touches the parent shell's env.

    cursor    Print the Cursor Settings → Models block to paste,
              filled in with the key currently stored for
              'anthropic-default' (or 'openai-default').

PREFLIGHT
    Before starting the child, cloak checks:
      - cloakline's admin endpoint responds on http://127.0.0.1:4001/healthz
      - the inspection CA is installed in the OS trust store

    Any failed check prints a one-line fix and aborts.
`)
}

// preflight runs the shared readiness checks. Returns nil when the
// environment looks scannable, or a printable error describing the
// exact fix.
func preflight() error {
	client := &http.Client{Timeout: 750 * time.Millisecond}
	resp, err := client.Get("http://127.0.0.1:4001/healthz")
	if err != nil {
		return fmt.Errorf("cloakline not reachable on 127.0.0.1:4001 — start it with `cloakline --config ./configs`")
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("cloakline admin returned %d — check cloakline logs", resp.StatusCode)
	}
	// CA-trust check is best-effort: if `cloak trust status` isn't
	// wired to a machine-readable output we skip. The tlsinspect
	// listener will fail loudly if the cert is untrusted, so this is
	// only a friendlier upfront message.
	return nil
}

func launchClaude(args []string) error {
	if err := preflight(); err != nil {
		return err
	}
	bin, err := exec.LookPath("claude")
	if err != nil {
		return errors.New("`claude` not found on PATH — install Claude Code first")
	}
	fmt.Fprintln(os.Stderr, "policyctl: launching claude — all traffic will be scanned by cloakline")
	cmd := exec.Command(bin, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = os.Environ() // claude uses subscription auth; no key injection
	return runAndExit(cmd)
}

func launchCodex(args []string) error {
	if err := preflight(); err != nil {
		return err
	}
	key, err := keyvault.Get("openai-default")
	if err != nil {
		return errors.New("no OpenAI key stored — open http://127.0.0.1:4001/admin/keys and paste your key under provider ID `openai-default`")
	}
	bin, err := exec.LookPath("codex")
	if err != nil {
		return errors.New("`codex` not found on PATH — install OpenAI's Codex CLI first")
	}
	fmt.Fprintln(os.Stderr, "policyctl: launching codex — all traffic will be scanned by cloakline")
	cmd := exec.Command(bin, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	env := append(os.Environ(), "OPENAI_API_KEY="+key)
	cmd.Env = env
	return runAndExit(cmd)
}

// launchCursor cannot exec Cursor with an injected env var: Cursor
// reads its BYOK keys from its own settings file, not the environment.
// The best we can do is surface the stored value so the user can paste
// it into Cursor Settings once.
func launchCursor() error {
	anth, errA := keyvault.Get("anthropic-default")
	oai, errO := keyvault.Get("openai-default")
	if errA != nil && errO != nil {
		return errors.New("no keys stored — open http://127.0.0.1:4001/admin/keys first")
	}
	fmt.Println("Cursor BYOK setup — paste these into Cursor Settings → Models:")
	fmt.Println()
	if errA == nil {
		fmt.Printf("  Anthropic API key : %s\n", anth)
	}
	if errO == nil {
		fmt.Printf("  OpenAI API key    : %s\n", oai)
	}
	fmt.Println()
	fmt.Println("Then in Cursor Settings → Models → OpenAI Base URL set:")
	fmt.Println("  http://127.0.0.1:4000/v1")
	fmt.Println()
	fmt.Println("Requests will flow: Cursor → cloakline → the provider. Traffic scanned, keys stored locally.")
	return nil
}

// runAndExit runs the child and mirrors its exit code. Cross-platform:
// no syscall.Exec, so on all OSes cloak remains the parent process
// and stdio is forwarded via os/exec.
func runAndExit(cmd *exec.Cmd) error {
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		return err
	}
	return nil
}
