package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"policyd/internal/dlp/patterns"
)

// cmdScan runs DLP patterns against a file or stdin. No gateway needed.
// This is the trust-generating dev command — a developer uses it before
// pasting code into ChatGPT / Claude / anywhere.
func cmdScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "Emit JSON instead of human-readable output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return errors.New("usage: policyctl scan <file>|- [--json]")
	}

	source, input, err := readInput(rest[0])
	if err != nil {
		return err
	}
	findings := patterns.Scan(input)

	if *asJSON {
		return writeJSON(findings, source)
	}
	return writeHuman(findings, source, input)
}

func readInput(arg string) (source string, content string, err error) {
	if arg == "-" {
		buf, rerr := io.ReadAll(io.LimitReader(os.Stdin, 8<<20))
		if rerr != nil {
			return "", "", fmt.Errorf("read stdin: %w", rerr)
		}
		return "<stdin>", string(buf), nil
	}
	buf, rerr := os.ReadFile(arg)
	if rerr != nil {
		return "", "", fmt.Errorf("read %s: %w", arg, rerr)
	}
	return arg, string(buf), nil
}

type jsonFinding struct {
	Kind  string `json:"kind"`
	Line  int    `json:"line"`
	Col   int    `json:"col"`
	Start int    `json:"start"`
	End   int    `json:"end"`
	Text  string `json:"text"`
}

type jsonReport struct {
	Source   string        `json:"source"`
	Total    int           `json:"total"`
	Findings []jsonFinding `json:"findings"`
}

func writeJSON(fs []patterns.Finding, source string) error {
	rep := jsonReport{Source: source, Total: len(fs)}
	for _, f := range fs {
		line, col := lineCol("", f.Start)
		rep.Findings = append(rep.Findings, jsonFinding{
			Kind:  string(f.Kind),
			Line:  line,
			Col:   col,
			Start: f.Start,
			End:   f.End,
			Text:  f.Text,
		})
	}
	return json.NewEncoder(os.Stdout).Encode(rep)
}

func writeHuman(fs []patterns.Finding, source, input string) error {
	if len(fs) == 0 {
		fmt.Printf("%s %s — no findings\n", green("✓"), bold(source))
		return nil
	}
	fmt.Printf("%s %s — %d finding%s\n\n",
		red("✗"), bold(source), len(fs), plural(len(fs)))
	for _, f := range fs {
		line, col := lineCol(input, f.Start)
		fmt.Printf("  %s %s at %s:%d:%d\n",
			red("●"),
			bold(string(f.Kind)),
			gray(source),
			line, col,
		)
		// Show a masked preview of the finding — only leading and trailing
		// chars so the operator can see WHICH one hit without staring at
		// the plaintext.
		fmt.Printf("      %s\n", mask(f.Text))
	}
	fmt.Printf("\n%s Do not paste this into a public AI service.\n",
		yellow("!"))
	return errors.New("findings present")
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// lineCol converts a byte offset into a 1-based line and column.
func lineCol(input string, offset int) (int, int) {
	if input == "" {
		return 0, 0
	}
	line, col := 1, 1
	for i, r := range input {
		if i >= offset {
			break
		}
		if r == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return line, col
}

// mask shows just enough of the finding to identify it without full disclosure.
func mask(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:3] + strings.Repeat("*", len(s)-6) + s[len(s)-3:]
}
