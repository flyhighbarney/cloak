package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"policyd/internal/tlsinspect"
)

// cmdTrust dispatches subcommands for the local inspection CA.
func cmdTrust(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: policyctl trust <show|status|install|remove>")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "show":
		return trustShow(rest)
	case "status":
		return trustStatus(rest)
	case "install":
		return trustInstall(rest)
	case "remove":
		return trustRemove(rest)
	}
	return fmt.Errorf("unknown trust subcommand: %s", sub)
}

// caDir returns the on-disk directory the CA lives in.
func caDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "policyd", "ca"), nil
}

func trustShow(_ []string) error {
	dir, err := caDir()
	if err != nil {
		return err
	}
	ca, err := tlsinspect.LoadOrCreate(dir)
	if err != nil {
		return err
	}
	certPath := ca.ExportedCertPath()
	fmt.Println(bold("Local inspection CA"))
	fmt.Printf("  cert: %s\n", cyan(certPath))
	fmt.Printf("  CN:   %s\n", ca.Cert.Subject.CommonName)
	fmt.Printf("  expires: %s\n", ca.Cert.NotAfter.Format("2006-01-02"))
	fmt.Println()
	fmt.Println(bold("To trust this CA on this machine:"))
	fmt.Println()
	fmt.Println("  " + cyan("policyctl trust install"))
	fmt.Println()
	fmt.Println("Or install manually:")
	fmt.Println()
	switch runtime.GOOS {
	case "windows":
		fmt.Printf("  certutil -user -addstore Root %q\n", certPath)
	case "darwin":
		fmt.Printf("  security add-trusted-cert -k ~/Library/Keychains/login.keychain-db %q\n", certPath)
	case "linux":
		fmt.Printf("  sudo cp %q /usr/local/share/ca-certificates/policyd-local.crt\n", certPath)
		fmt.Println("  sudo update-ca-certificates")
	}
	fmt.Println()
	fmt.Println(gray("You can undo either with `policyctl trust remove`."))
	return nil
}

func trustStatus(_ []string) error {
	dir, err := caDir()
	if err != nil {
		return err
	}
	certPath := filepath.Join(dir, "ca-cert.pem")
	if _, err := os.Stat(certPath); errors.Is(err, os.ErrNotExist) {
		fmt.Printf("%s no local CA yet — run %s\n", yellow("!"), cyan("policyctl trust show"))
		return nil
	}
	fmt.Printf("%s CA file present at %s\n", green("✓"), gray(certPath))
	if inOSStore(certPath) {
		fmt.Printf("%s CA is installed in the current user's trust store\n", green("✓"))
	} else {
		fmt.Printf("%s CA is not in the OS trust store (or check is inconclusive)\n", yellow("!"))
		fmt.Printf("      run: %s\n", cyan("policyctl trust install"))
	}
	return nil
}

func trustInstall(args []string) error {
	fs := flag.NewFlagSet("trust install", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "Skip the confirmation prompt")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir, err := caDir()
	if err != nil {
		return err
	}
	ca, err := tlsinspect.LoadOrCreate(dir)
	if err != nil {
		return err
	}
	certPath := ca.ExportedCertPath()

	if !*yes {
		fmt.Println(bold("You are about to trust a new certificate authority on this machine."))
		fmt.Println()
		fmt.Printf("  CA:      %s\n", ca.Cert.Subject.CommonName)
		fmt.Printf("  scope:   current user only\n")
		fmt.Printf("  cert:    %s\n", certPath)
		fmt.Printf("  purpose: policyd local inspection (see docs/inspect.md)\n")
		fmt.Println()
		fmt.Println("This lets policyd terminate TLS locally on your own machine so")
		fmt.Println("its DLP layer can scan AI-provider request bodies before they leave.")
		fmt.Println()
		fmt.Println("This does NOT trust anything from anywhere else.")
		fmt.Println()
		fmt.Print("Proceed? [y/N] ")
		r := bufio.NewReader(os.Stdin)
		ans, _ := r.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(ans)) != "y" {
			return errors.New("cancelled")
		}
	}

	if err := installToOSStore(certPath); err != nil {
		return err
	}
	fmt.Printf("%s CA installed into %s trust store\n", green("✓"), runtime.GOOS)
	return nil
}

func trustRemove(args []string) error {
	fs := flag.NewFlagSet("trust remove", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "Skip the confirmation prompt")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir, err := caDir()
	if err != nil {
		return err
	}
	certPath := filepath.Join(dir, "ca-cert.pem")

	if !*yes {
		fmt.Printf("Remove the local inspection CA from the OS trust store and delete %s? [y/N] ", certPath)
		r := bufio.NewReader(os.Stdin)
		ans, _ := r.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(ans)) != "y" {
			return errors.New("cancelled")
		}
	}
	if err := removeFromOSStore(certPath); err != nil {
		fmt.Fprintf(os.Stderr, "%s remove from OS store failed: %v\n", yellow("!"), err)
	}
	_ = os.Remove(certPath)
	_ = os.Remove(filepath.Join(dir, "ca-key.pem"))
	fmt.Printf("%s local CA removed. Re-create with `policyctl trust show`.\n", green("✓"))
	return nil
}

// -------- OS-specific bridges --------

func installToOSStore(certPath string) error {
	switch runtime.GOOS {
	case "windows":
		return run("certutil", "-user", "-addstore", "Root", certPath)
	case "darwin":
		home, _ := os.UserHomeDir()
		return run("security", "add-trusted-cert",
			"-k", filepath.Join(home, "Library", "Keychains", "login.keychain-db"),
			certPath)
	case "linux":
		return fmt.Errorf("linux install requires root; run: sudo cp %s /usr/local/share/ca-certificates/policyd-local.crt && sudo update-ca-certificates", certPath)
	}
	return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
}

func removeFromOSStore(certPath string) error {
	switch runtime.GOOS {
	case "windows":
		// certutil identifies by CN or thumbprint.
		return run("certutil", "-user", "-delstore", "Root", "policyd local inspection CA")
	case "darwin":
		return run("security", "delete-certificate", "-c", "policyd local inspection CA")
	case "linux":
		return errors.New("linux: sudo rm /usr/local/share/ca-certificates/policyd-local.crt && sudo update-ca-certificates")
	}
	return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
}

func inOSStore(certPath string) bool {
	// Best-effort — different OSes have different check mechanisms. Never
	// treat this as authoritative; when in doubt, print the install command.
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("certutil", "-user", "-store", "Root", "policyd local inspection CA").CombinedOutput()
		return err == nil && strings.Contains(string(out), "policyd local inspection CA")
	}
	return false
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v — %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
