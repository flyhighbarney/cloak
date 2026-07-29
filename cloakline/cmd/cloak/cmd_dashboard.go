package main

import (
	"fmt"
	"os/exec"
	"runtime"
)

const adminURL = "http://127.0.0.1:4001/admin"

// cmdDashboard opens the admin web dashboard in the default browser.
// If cloakline isn't running, the browser will show a connection-refused
// page and a hint is printed to the terminal.
func cmdDashboard(_ []string) error {
	fmt.Printf("  Opening %s\n", cyan(adminURL))
	if err := openBrowser(adminURL); err != nil {
		fmt.Printf("  %s Could not open browser: %v\n", yellow("!"), err)
		fmt.Printf("  Navigate to %s manually.\n", cyan(adminURL))
	}
	return nil
}

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("cmd", "/c", "start", url).Run()
	case "darwin":
		return exec.Command("open", url).Run()
	default:
		return exec.Command("xdg-open", url).Run()
	}
}
