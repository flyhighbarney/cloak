//go:build windows

package notify

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type windowsNotifier struct{}

// New returns a Notifier backed by a Windows WinForms balloon tip that
// appears near the system tray. Requires powershell.exe and the
// System.Windows.Forms assembly (present on all supported Windows
// versions). The tray icon is transient — it appears only for the
// duration of the balloon (≤13 seconds).
func New() Notifier { return &windowsNotifier{} }

func (n *windowsNotifier) Close() {}

// Notify fires the balloon in a background goroutine so the request
// handler is never delayed. Only fires when a Claude-related process
// (Desktop or CLI) is running — avoids phantom alerts when cloakline
// is running but the user isn't using Claude right now.
func (n *windowsNotifier) Notify(kind, allowURL string) {
	if !anyClaudeRunning() {
		return
	}
	go showBalloon(kind, allowURL)
}

// anyClaudeRunning checks whether Claude Desktop (Claude.exe) or the
// Claude CLI (claude.exe) is currently running. Uses tasklist /FI which
// is case-insensitive on Windows.
func anyClaudeRunning() bool {
	out, err := exec.Command(
		"tasklist",
		"/FI", "IMAGENAME eq Claude.exe",
		"/NH", "/FO", "CSV",
	).Output()
	if err == nil && strings.Contains(strings.ToLower(string(out)), "claude.exe") {
		return true
	}
	// Also catch the lowercase CLI binary name used by some installs.
	out2, err2 := exec.Command(
		"tasklist",
		"/FI", "IMAGENAME eq claude.exe",
		"/NH", "/FO", "CSV",
	).Output()
	return err2 == nil && strings.Contains(strings.ToLower(string(out2)), "claude.exe")
}

// showBalloon writes a temp PowerShell script that creates a transient
// WinForms NotifyIcon, shows a balloon tip with two buttons, runs a
// Windows message loop until the balloon is dismissed (or 13 seconds
// pass), then cleans up.
//
// Env vars carry the strings to avoid PowerShell quoting issues.
func showBalloon(kind, allowURL string) {
	const script = `
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$title   = $env:CL_TITLE
$body    = $env:CL_BODY
$url     = $env:CL_URL

$ni = [System.Windows.Forms.NotifyIcon]::new()
$ni.Icon = [System.Drawing.SystemIcons]::Shield
$ni.Visible = $true
$ni.BalloonTipIcon   = [System.Windows.Forms.ToolTipIcon]::Warning
$ni.BalloonTipTitle  = $title
$ni.BalloonTipText   = $body

$ni.add_BalloonTipClicked({
    [System.Diagnostics.Process]::Start($url) | Out-Null
    [System.Windows.Forms.Application]::Exit()
})
$ni.add_BalloonTipClosed({
    [System.Windows.Forms.Application]::Exit()
})

$ni.ShowBalloonTip(12000)

$t = [System.Windows.Forms.Timer]::new()
$t.Interval = 13000
$t.add_Tick({
    $t.Stop()
    [System.Windows.Forms.Application]::Exit()
})
$t.Start()

[System.Windows.Forms.Application]::Run()
$ni.Visible = $false
$ni.Dispose()
`
	f, err := os.CreateTemp("", "cloakline-notify-*.ps1")
	if err != nil {
		return
	}
	path := f.Name()
	defer os.Remove(path)

	if _, err := f.WriteString(script); err != nil {
		f.Close()
		return
	}
	f.Close()

	cmd := exec.Command(
		"powershell",
		"-NoProfile",
		"-WindowStyle", "Hidden",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-File", path,
	)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("CL_TITLE=cloakline: %s blocked", kind),
		fmt.Sprintf("CL_BODY=A %s was redacted before reaching the AI. Click to allow this session, then resend your message.", kind),
		fmt.Sprintf("CL_URL=%s", allowURL),
	)
	_ = cmd.Run()
}
