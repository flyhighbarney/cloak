package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// tty checks if stdout is a terminal. Colors are disabled when it isn't
// (piped output, CI logs, etc.).
var tty = func() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}()

const (
	cReset  = "\x1b[0m"
	cRed    = "\x1b[31m"
	cGreen  = "\x1b[32m"
	cYellow = "\x1b[33m"
	cBlue   = "\x1b[34m"
	cCyan   = "\x1b[36m"
	cGray   = "\x1b[90m"
	cBold   = "\x1b[1m"
)

func color(code, s string) string {
	if !tty {
		return s
	}
	return code + s + cReset
}

// paint helpers.
func red(s string) string    { return color(cRed, s) }
func green(s string) string  { return color(cGreen, s) }
func yellow(s string) string { return color(cYellow, s) }
func blue(s string) string   { return color(cBlue, s) }
func cyan(s string) string   { return color(cCyan, s) }
func gray(s string) string   { return color(cGray, s) }
func bold(s string) string   { return color(cBold, s) }

func infof(w io.Writer, format string, args ...any) {
	fmt.Fprintln(w, fmt.Sprintf(format, args...))
}

// printBanner prints the cloakline setup header.
func printBanner(version string) {
	w := 55
	line := strings.Repeat("─", w)
	fmt.Println()
	fmt.Printf("  ┌%s┐\n", line)
	fmt.Printf("  │%s│\n", strings.Repeat(" ", w))
	fmt.Printf("  │   %-*s│\n", w-3, bold(cyan("CLOAKLINE"))+"   "+gray("AI security gateway"))
	fmt.Printf("  │   %-*s│\n", w-3, gray("version ")+version+strings.Repeat(" ", w-3-len("version ")-len(version)))
	fmt.Printf("  │%s│\n", strings.Repeat(" ", w))
	fmt.Printf("  └%s┘\n", line)
	fmt.Println()
}

// spinner starts an animated status indicator for a slow operation.
// Call the returned stop function when the operation finishes.
// Prints a plain message on non-TTY outputs.
func spinner(label string) func(ok bool) {
	if !tty {
		fmt.Printf("  %s... ", label)
		return func(ok bool) {
			if ok {
				fmt.Printf("%s\n", green("done"))
			} else {
				fmt.Printf("%s\n", red("failed"))
			}
		}
	}
	frames := []byte{'-', '\\', '|', '/'}
	quit := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		i := 0
		for {
			select {
			case <-quit:
				fmt.Printf("\r%s\r", strings.Repeat(" ", len(label)+12))
				return
			default:
				fmt.Printf("\r  %c  %s", frames[i%len(frames)], label)
				i++
				time.Sleep(80 * time.Millisecond)
			}
		}
	}()
	return func(ok bool) {
		close(quit)
		<-stopped
		if ok {
			fmt.Printf("  %s  %s\n", green("✓"), label)
		} else {
			fmt.Printf("  %s  %s\n", red("✗"), label)
		}
	}
}
