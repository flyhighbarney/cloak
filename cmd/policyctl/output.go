package main

import (
	"fmt"
	"io"
	"os"
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
