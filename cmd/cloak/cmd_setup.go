package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"cloakline/internal/keyvault"
)

// cmdSetup is the one-time interactive setup. When it finishes, the
// user can type `claude`, `codex`, or use Cursor and every request
// goes through cloakline invisibly.
//
// What it does, in order:
//  1. Install the local inspection CA into the OS trust store.
//  2. Prompt for each supported provider's API key and save it to
//     the OS keyring.
//  3. Enable the inspection module in configs/pipeline.yaml so
//     cloakline starts the transparent scanner on next boot.
//  4. Print the exact hosts-file lines to add, or offer to add them
//     if the current process is already elevated.
//  5. Optionally install a Windows startup shortcut so cloakline runs
//     on login.
//
// Everything is idempotent — running setup a second time updates
// keys, re-verifies the CA, and does not duplicate config edits.
func cmdSetup(args []string) error {
	printBanner(Version)

	fmt.Println(gray("Run this once. After it finishes, use `claude`, `codex`, or Cursor normally."))
	fmt.Println()

	// Install the OS-native keyring backend up front so keys we
	// collect below get persisted, not held in memory.
	stop := spinner("Initialising secure key vault")
	_, kvErr := keyvault.Install()
	stop(kvErr == nil)
	if kvErr != nil {
		fmt.Fprintf(os.Stderr, "  %s keyvault: %v\n", yellow("!"), kvErr)
		fmt.Fprintln(os.Stderr, "    Keys will not persist across restarts on this platform.")
	}
	fmt.Println()

	// Step 1 — CA trust.
	// Pass --yes to skip the standalone confirmation prompt: the wizard
	// banner already explains what the CA is and why it's needed.
	fmt.Println(bold("Step 1 / 4 — install local inspection CA"))
	if err := trustInstall([]string{"--yes"}); err != nil {
		return fmt.Errorf("could not install CA: %w", err)
	}
	fmt.Println()

	// Step 2 — API keys.
	fmt.Println(bold("Step 2 / 4 — save your provider API keys"))
	fmt.Println(gray("Paste each key when prompted, or press Enter to skip."))
	fmt.Println(gray("On Windows these are DPAPI-encrypted under your user account."))
	fmt.Println()
	rd := bufio.NewReader(os.Stdin)
	for _, prov := range setupProviders {
		if err := promptAndStore(rd, prov.id, prov.label); err != nil {
			return err
		}
	}
	fmt.Println()

	// Step 3 — enable inspection.
	fmt.Println(bold("Step 3 / 4 — enable transparent inspection"))
	if changed, err := enableInspect("configs/pipeline.yaml"); err != nil {
		fmt.Printf("  %s could not update configs/pipeline.yaml: %v\n", yellow("!"), err)
		fmt.Println("  Edit it manually and set `inspect.enabled: true`.")
	} else if changed {
		fmt.Printf("  %s inspect.enabled: true (was disabled)\n", green("✓"))
	} else {
		fmt.Printf("  %s inspect already enabled\n", green("✓"))
	}
	fmt.Println()

	// Step 4 — hosts-file guidance.
	fmt.Println(bold("Step 4 / 4 — direct AI-provider hostnames at cloakline"))
	printHostsGuidance()
	fmt.Println()

	// Optional — autostart.
	if runtime.GOOS == "windows" {
		fmt.Println(bold("Optional — start cloakline automatically on login?"))
		if askYesNo(rd, "Add a startup shortcut for cloakline.exe?", false) {
			if err := installWindowsAutostart(); err != nil {
				fmt.Printf("  %s could not add startup shortcut: %v\n", yellow("!"), err)
			} else {
				fmt.Printf("  %s cloakline will start on your next login\n", green("✓"))
			}
		}
		fmt.Println()
	}

	fmt.Println(bold("Setup complete."))
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Start cloakline (or reboot if you enabled autostart):")
	fmt.Println("       " + cyan("./bin/cloakline.exe --config ./configs"))
	fmt.Println("  2. Open the dashboard:")
	fmt.Println("       " + cyan("http://127.0.0.1:4001/admin"))
	fmt.Println("  3. Use your CLIs normally — no wrapper needed:")
	fmt.Println("       " + cyan("claude -p \"hello\""))
	fmt.Println("       " + cyan("codex \"print hi\""))
	fmt.Println()
	fmt.Println(gray("Everything is scanned silently. Redactions happen in the background;"))
	fmt.Println(gray("only outright-blocked requests surface an error in your CLI."))
	return nil
}

type providerPrompt struct {
	id    string // matches the key used in configs/providers.yaml and keyvault
	label string // human name shown in the prompt
}

var setupProviders = []providerPrompt{
	{id: "anthropic-default", label: "Anthropic (Claude / Claude Code CLI)"},
	{id: "openai-default", label: "OpenAI (Codex CLI, ChatGPT SDKs)"},
}

func promptAndStore(rd *bufio.Reader, providerID, label string) error {
	existing, err := keyvault.Get(providerID)
	if err == nil && existing != "" {
		fmt.Printf("  %s %s — already stored (%s). Enter a new key to replace, or press Enter to keep.\n",
			green("✓"), label, keyvault.Mask(existing))
	} else {
		fmt.Printf("    %s\n", label)
	}
	fmt.Printf("    key: ")
	line, err := rd.ReadString('\n')
	if err != nil {
		return err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		if existing == "" {
			fmt.Printf("    %s skipped\n", gray("·"))
		}
		return nil
	}
	if err := keyvault.Set(providerID, line); err != nil {
		return fmt.Errorf("save %s: %w", providerID, err)
	}
	fmt.Printf("    %s stored as %s\n", green("✓"), keyvault.Mask(line))
	return nil
}

func askYesNo(rd *bufio.Reader, prompt string, def bool) bool {
	suffix := " [y/N]"
	if def {
		suffix = " [Y/n]"
	}
	fmt.Printf("  %s%s ", prompt, suffix)
	line, err := rd.ReadString('\n')
	if err != nil {
		return def
	}
	line = strings.ToLower(strings.TrimSpace(line))
	if line == "" {
		return def
	}
	return line == "y" || line == "yes"
}

// enableInspect flips the top-level `inspect.enabled` flag to true.
// Text-level edit — we don't parse YAML into a struct because the file
// has comments the user cares about and marshaling would strip them.
//
// Returns (changed, err). changed=false means the flag was already
// true, which is the normal case on a second setup run.
func enableInspect(path string) (bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	text := string(raw)

	// Case A: file has `enabled: false` under an inspect: block.
	if strings.Contains(text, "\ninspect:") {
		if strings.Contains(text, "  enabled: true") {
			return false, nil
		}
		updated := strings.Replace(text, "  enabled: false", "  enabled: true", 1)
		if updated == text {
			// The section exists but with different formatting we
			// don't want to guess at. Bail — user must edit manually.
			return false, errors.New("inspect block found but not in the expected shape")
		}
		return true, os.WriteFile(path, []byte(updated), 0o644)
	}

	// Case B: no inspect block at all. Append one.
	block := "\n\n# Added by `cloak setup`.\ninspect:\n  enabled: true\n  listen: \":8443\"\n  hosts:\n    - api.openai.com\n    - api.anthropic.com\n"
	return true, os.WriteFile(path, []byte(text+block), 0o644)
}

func printHostsGuidance() {
	switch runtime.GOOS {
	case "windows":
		fmt.Println(gray("  cloakline needs `api.openai.com` and `api.anthropic.com` to resolve"))
		fmt.Println(gray("  to 127.0.0.1 so it can intercept and scan traffic. Adding these"))
		fmt.Println(gray("  lines requires admin rights — I won't do it automatically."))
		fmt.Println()
		fmt.Println("  Open Notepad as Administrator and edit:")
		fmt.Println("    " + cyan(`C:\Windows\System32\drivers\etc\hosts`))
		fmt.Println("  Add these two lines:")
		fmt.Println("    " + cyan("127.0.0.1 api.anthropic.com"))
		fmt.Println("    " + cyan("127.0.0.1 api.openai.com"))
		fmt.Println()
		fmt.Println(gray("  Then in configs/pipeline.yaml, change `inspect.listen: \":8443\"`"))
		fmt.Println(gray("  to `inspect.listen: \":443\"` and start cloakline as Administrator."))
	case "darwin":
		fmt.Println("  sudo sh -c \"echo '127.0.0.1 api.anthropic.com' >> /etc/hosts\"")
		fmt.Println("  sudo sh -c \"echo '127.0.0.1 api.openai.com'    >> /etc/hosts\"")
	case "linux":
		fmt.Println("  sudo sh -c \"echo '127.0.0.1 api.anthropic.com' >> /etc/hosts\"")
		fmt.Println("  sudo sh -c \"echo '127.0.0.1 api.openai.com'    >> /etc/hosts\"")
	}
}

// installWindowsAutostart drops a .cmd file into the user's Startup
// folder that launches cloakline on login. A .cmd wrapper (not a raw
// shortcut) lets us pass the --config flag reliably.
func installWindowsAutostart() error {
	if runtime.GOOS != "windows" {
		return errors.New("autostart is Windows-only in this release")
	}
	// Where the current cloakline binary lives — assumes ./bin/cloakline.exe
	// relative to the current working directory when setup ran.
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	exePath := filepath.Join(wd, "bin", "cloakline.exe")
	cfgPath := filepath.Join(wd, "configs")
	if _, err := os.Stat(exePath); err != nil {
		return fmt.Errorf("cloakline.exe not found at %s — build it first with `make build`", exePath)
	}

	appdata := os.Getenv("APPDATA")
	if appdata == "" {
		return errors.New("APPDATA not set")
	}
	startup := filepath.Join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
	if err := os.MkdirAll(startup, 0o755); err != nil {
		return err
	}
	target := filepath.Join(startup, "cloakline.cmd")
	body := fmt.Sprintf("@echo off\r\nstart \"\" /min \"%s\" --config \"%s\"\r\n", exePath, cfgPath)
	return os.WriteFile(target, []byte(body), 0o644)
}
