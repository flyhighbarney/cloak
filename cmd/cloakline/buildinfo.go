package main

import (
	"runtime/debug"
	"strings"
)

// Build stamps. These are overridden at release/build time via
//
//	-ldflags "-X main.version=v0.1.3 -X main.commit=<sha> -X main.buildTime=<iso8601>"
//
// (see the Makefile and .github/workflows/release.yml). When built with a
// plain `go build` and no ldflags, they stay at their dev defaults and we
// fall back to the VCS info Go embeds automatically in the binary — so even
// an un-stamped local build still reports the commit it came from.
var (
	version   = "dev"
	commit    = ""
	buildTime = ""
)

// buildInfo is the resolved build identity for this binary.
type buildInfo struct {
	Version   string // release tag or "dev"
	Commit    string // full git sha, "" if unknown
	Short     string // first 12 chars of Commit, "" if unknown
	BuildTime string // ISO-8601 build timestamp, "" if unknown
	Dirty     bool   // built from a modified working tree
}

// resolveBuildInfo merges the ldflags-injected stamps with the VCS metadata
// Go bakes into the binary via runtime/debug. ldflags win when present; the
// embedded VCS data fills the gaps for local `go build`/`go run`.
func resolveBuildInfo() buildInfo {
	bi := buildInfo{Version: version, Commit: commit, BuildTime: buildTime}

	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				if bi.Commit == "" {
					bi.Commit = s.Value
				}
			case "vcs.time":
				if bi.BuildTime == "" {
					bi.BuildTime = s.Value
				}
			case "vcs.modified":
				bi.Dirty = s.Value == "true"
			}
		}
	}

	if len(bi.Commit) >= 12 {
		bi.Short = bi.Commit[:12]
	} else {
		bi.Short = bi.Commit
	}
	return bi
}

// logFields returns the compact identity attached to every log line so a
// pasted log immediately reveals which build produced it. This is the single
// fact that turns "is the running daemon the one with my fix?" from a
// guessing game into a lookup: match commit against `git log`.
func (b buildInfo) logFields() map[string]any {
	f := map[string]any{"ver": b.Version}
	if b.Short != "" {
		c := b.Short
		if b.Dirty {
			c += "-dirty"
		}
		f["commit"] = c
	}
	return f
}

// String is the human-readable one-liner for the startup banner.
func (b buildInfo) String() string {
	var sb strings.Builder
	sb.WriteString(b.Version)
	if b.Short != "" {
		sb.WriteString(" (")
		sb.WriteString(b.Short)
		if b.Dirty {
			sb.WriteString("-dirty")
		}
		sb.WriteString(")")
	}
	if b.BuildTime != "" {
		sb.WriteString(" built ")
		sb.WriteString(b.BuildTime)
	}
	return sb.String()
}
