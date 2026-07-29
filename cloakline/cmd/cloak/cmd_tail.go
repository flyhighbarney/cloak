package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"
)

// tailStats mirrors audit.Stats for JSON decoding.
type tailStats struct {
	Total                     uint64 `json:"Total"`
	Allowed                   int    `json:"Allowed"`
	Redacted                  int    `json:"Redacted"`
	Warned                    int    `json:"Warned"`
	BlockedDLP                int    `json:"BlockedDLP"`
	BlockedPolicy             int    `json:"BlockedPolicy"`
	UpstreamErrors            int    `json:"UpstreamErrors"`
	AuthFailures              int    `json:"AuthFailures"`
	Buffered                  int    `json:"Buffered"`
	LifetimeSecretsCaught     uint64 `json:"LifetimeSecretsCaught"`
	LifetimePIIRedacted       uint64 `json:"LifetimePIIRedacted"`
	LifetimeInjectionsBlocked uint64 `json:"LifetimeInjectionsBlocked"`
}

// tailEntry mirrors adminui.apiEntry for JSON decoding.
type tailEntry struct {
	Timestamp   string   `json:"timestamp"`
	Verdict     string   `json:"verdict"`
	Endpoint    string   `json:"endpoint"`
	Model       string   `json:"model"`
	DLPFindings []string `json:"dlp_findings"`
	DurationMS  int64    `json:"duration_ms"`
}

// cmdTail runs a live terminal dashboard polling the local admin API.
// No gateway config needed — it talks directly to 127.0.0.1:4001.
func cmdTail(_ []string) error {
	const adminBase = "http://127.0.0.1:4001"
	client := &http.Client{Timeout: 2 * time.Second}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Reset(os.Interrupt)

	if tty {
		fmt.Print("\033[?25l") // hide cursor
		defer fmt.Print("\033[?25h\n")
	}

	drawTail(client, adminBase)
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()

	for {
		select {
		case <-sigCh:
			return nil
		case <-tick.C:
			drawTail(client, adminBase)
		}
	}
}

const tailInnerW = 64

func drawTail(client *http.Client, base string) {
	var stats tailStats
	var entries []tailEntry
	statsErr := tailFetchJSON(client, base+"/admin/api/status", &stats)
	_ = tailFetchJSON(client, base+"/admin/api/recent?n=10", &entries)

	if tty {
		fmt.Print("\033[H\033[J") // go home, erase screen
	}

	hr := strings.Repeat("─", tailInnerW)
	fmt.Printf("┌%s┐\n", hr)

	// Header row — title left, timestamp right.
	title := " cloakline  live monitor"
	ts := "updated " + time.Now().UTC().Format("15:04:05") + " UTC "
	gap := tailInnerW - len(title) - len(ts)
	if gap < 0 {
		gap = 0
	}
	headerLine := title + strings.Repeat(" ", gap) + ts
	fmt.Printf("│%s│\n", bold(headerLine))
	fmt.Printf("├%s┤\n", hr)

	if statsErr != nil {
		errLine := tailPad("  "+red("✗")+"  cloakline unreachable on 127.0.0.1:4001", tailInnerW, 4)
		hintLine := tailPad("     run: "+cyan("cloakline --config ./configs"), tailInnerW, 0)
		emptyLine := strings.Repeat(" ", tailInnerW)
		fmt.Printf("│%s│\n", emptyLine)
		fmt.Printf("│%s│\n", errLine)
		fmt.Printf("│%s│\n", hintLine)
		fmt.Printf("│%s│\n", emptyLine)
		fmt.Printf("└%s┘\n", hr)
		fmt.Println(gray("  Retrying every 2s — Ctrl-C to exit"))
		return
	}

	// Stats tiles: 4 columns of tailInnerW/4 = 16 chars each.
	col := tailInnerW / 4
	h1 := tailFixW("  TOTAL SCANNED", col) + tailFixW("  SECRETS CAUGHT", col) +
		tailFixW("  PII REDACTED", col) + tailFixW("  INJECTIONS", col)
	v1 := tailFixW("  "+cyan(fmt.Sprintf("%d", stats.Total)), col) +
		tailFixW("  "+green(fmt.Sprintf("%d", stats.LifetimeSecretsCaught)), col) +
		tailFixW("  "+yellow(fmt.Sprintf("%d", stats.LifetimePIIRedacted)), col) +
		tailFixW("  "+red(fmt.Sprintf("%d", stats.LifetimeInjectionsBlocked)), col)
	// v1 contains ANSI codes; visual width is tailInnerW but string len is larger.
	fmt.Printf("│%s│\n", gray(h1))
	fmt.Printf("│%s│\n", tailAnsiRow(v1, tailInnerW))
	fmt.Printf("├%s┤\n", hr)

	// Recent activity section.
	recentTitle := "  RECENT ACTIVITY"
	recentRight := "live  "
	recentGap := tailInnerW - len(recentTitle) - len(recentRight)
	if recentGap < 0 {
		recentGap = 0
	}
	recentHeader := recentTitle + strings.Repeat(" ", recentGap) + recentRight
	fmt.Printf("│%s│\n", bold(recentHeader))

	// Column widths for table rows (must sum to tailInnerW):
	// "  " (2) + time(8) + "  " (2) + status(8) + "  " (2) + endpoint(22) + "  " (2) + dlp(18) = 64
	const (
		timeW     = 8
		statusW   = 8
		endpointW = 22
		dlpW      = 18
	)
	tblHdr := "  " + tailFixW("TIME", timeW) + "  " + tailFixW("STATUS", statusW) +
		"  " + tailFixW("ENDPOINT", endpointW) + "  " + tailFixW("DLP", dlpW)
	fmt.Printf("│%s│\n", gray(tblHdr))

	if len(entries) == 0 {
		emptyRow := "  " + gray("no requests yet") + strings.Repeat(" ", tailInnerW-2-len("no requests yet"))
		fmt.Printf("│%s│\n", emptyRow)
	}

	maxRows := 8
	for i, e := range entries {
		if i >= maxRows {
			break
		}

		// Parse timestamp to HH:MM:SS.
		rowTime := e.Timestamp
		if len(rowTime) >= 19 {
			rowTime = rowTime[11:19]
		}
		rowTime = tailFixW(rowTime, timeW)

		// Short verdict + color.
		shortV, colorFn := verdictShort(e.Verdict)
		statusText := tailFixW(shortV, statusW)    // visual width = statusW
		statusColored := colorFn(statusText)        // visual width unchanged, string len grows

		endpoint := tailFixW(e.Endpoint, endpointW)
		dlp := strings.Join(e.DLPFindings, ",")
		dlp = tailFixW(dlp, dlpW)

		// Build row: fixed-visual-width prefix + colored status + rest.
		// Visual width: 2 + timeW + 2 + statusW + 2 + endpointW + 2 + dlpW = 64 ✓
		prefix := "  " + rowTime + "  "                               // visual: 2+timeW+2 = 12
		suffix := "  " + endpoint + "  " + dlp                        // visual: 2+endpointW+2+dlpW = 44
		// Total visual: 12 + statusW + 44 = 64 ✓

		fmt.Printf("│%s%s%s│\n", prefix, statusColored, suffix)
	}

	fmt.Printf("└%s┘\n", hr)
	fmt.Println(gray("  Ctrl-C to exit · refreshes every 2s"))
}

// verdictShort returns a fixed short label and a color function for a verdict string.
func verdictShort(v string) (string, func(string) string) {
	switch v {
	case "allowed":
		return "ALLOW", green
	case "redacted":
		return "REDACT", yellow
	case "warned":
		return "WARN", yellow
	case "blocked_dlp", "blocked_policy":
		return "BLOCK", red
	case "upstream_error":
		return "ERROR", red
	case "auth_failed":
		return "AUTH", red
	default:
		return v, gray
	}
}

// tailFixW truncates or right-pads s to exactly w visual chars.
// No ANSI codes — purely for layout.
func tailFixW(s string, w int) string {
	r := []rune(s)
	if len(r) >= w {
		return string(r[:w])
	}
	return s + strings.Repeat(" ", w-len(r))
}

// tailPad pads a string that contains ANSI codes to visual width w.
// ansiExtra is the number of invisible ANSI bytes already in s.
func tailPad(s string, w, ansiExtra int) string {
	visLen := len(s) - ansiExtra
	pad := w - visLen
	if pad < 0 {
		pad = 0
	}
	return s + strings.Repeat(" ", pad)
}

// tailAnsiRow takes a row string that already has the correct visual width
// (tailInnerW) but whose string length is greater due to ANSI codes.
// Prints it between │ borders using fmt.Printf %s (which does not pad).
func tailAnsiRow(s string, _ int) string {
	return s
}

func tailFetchJSON(client *http.Client, url string, out any) error {
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return json.Unmarshal(body, out)
}
