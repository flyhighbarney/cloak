package main

import "fmt"

const logsURL = "http://127.0.0.1:4001/admin/logs"

// cmdLogs opens the admin dashboard's Logs tab in the default browser,
// where the log file's contents can be copied and pasted for debugging.
func cmdLogs(_ []string) error {
	fmt.Printf("  Opening %s\n", cyan(logsURL))
	if err := openBrowser(logsURL); err != nil {
		fmt.Printf("  %s Could not open browser: %v\n", yellow("!"), err)
		fmt.Printf("  Navigate to %s manually.\n", cyan(logsURL))
	}
	return nil
}
