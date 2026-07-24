#!/usr/bin/env bash
# cloakline one-shot installer — macOS.
#
# Does everything from a fresh clone in one command:
#   1. Verifies Go 1.22+ is on PATH (fast-fail before sudo prompt).
#   2. Builds both binaries with `go build`.
#   3. Trusts the local inspection CA (macOS Keychain security dialog
#      may appear — click Always Trust).
#   4. Chains to scripts/install.sh which handles pipeline.yaml, the
#      pf redirect for :443 -> :8443, the LaunchAgent, listener
#      verification, hosts entries, and DNS verification.
#
# Usage:
#   ./scripts/bootstrap.sh
#
# Flags:
#   --skip-build   Skip `go build` (use existing bin/*)
#   --skip-trust   Skip CA install (assume already trusted)

set -euo pipefail

SKIP_BUILD=0
SKIP_TRUST=0
for arg in "$@"; do
    case "$arg" in
        --skip-build) SKIP_BUILD=1 ;;
        --skip-trust) SKIP_TRUST=1 ;;
        -h|--help)
            sed -n '2,20p' "$0"
            exit 0
            ;;
        *)
            printf "unknown flag: %s\n" "$arg" >&2
            exit 2
            ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="$REPO_ROOT/bin"
DAEMON_EXE="$BIN_DIR/cloakline"
CLOAK_EXE="$BIN_DIR/cloak"
INSTALL_SH="$REPO_ROOT/scripts/install.sh"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    CY="\033[36m"; GR="\033[32m"; RE="\033[31m"; YE="\033[33m"; GY="\033[90m"; NC="\033[0m"
else
    CY=""; GR=""; RE=""; YE=""; GY=""; NC=""
fi

printf "\n%b  cloakline bootstrap%b\n" "$CY" "$NC"
printf "  %brepo: %s%b\n\n" "$GY" "$REPO_ROOT" "$NC"

# --- Preflight: Go on PATH -----------------------------------------------

if [ $SKIP_BUILD -eq 0 ]; then
    if ! command -v go > /dev/null 2>&1; then
        printf "  %bGo compiler not found on PATH.%b\n" "$RE" "$NC"
        printf "  Install Go 1.22+ from %bhttps://go.dev/dl/%b and re-run,\n" "$CY" "$NC"
        printf "  or pre-build the binaries and re-run with --skip-build.\n"
        exit 1
    fi
fi

# --- Step 1: build -------------------------------------------------------

if [ $SKIP_BUILD -eq 0 ]; then
    printf "%b[1/3] Building binaries...%b\n" "$CY" "$NC"
    mkdir -p "$BIN_DIR"
    (
        cd "$REPO_ROOT"
        printf "  %bcompiling cloakline (daemon)...%b\n" "$GY" "$NC"
        go build -trimpath -o "$DAEMON_EXE" ./cmd/cloakline
        printf "  %bcompiling cloak (CLI)...%b\n" "$GY" "$NC"
        go build -trimpath -o "$CLOAK_EXE"  ./cmd/cloak
    )
    printf "  %b✓%b both binaries built\n" "$GR" "$NC"
else
    printf "%b[1/3] Skipping build (as requested)%b\n" "$GY" "$NC"
    if [ ! -x "$DAEMON_EXE" ] || [ ! -x "$CLOAK_EXE" ]; then
        printf "  %bMissing bin/cloakline or bin/cloak. Re-run without --skip-build.%b\n" "$RE" "$NC"
        exit 1
    fi
fi

# --- Step 2: trust CA ----------------------------------------------------

if [ $SKIP_TRUST -eq 0 ]; then
    printf "\n%b[2/3] Installing local inspection CA...%b\n" "$CY" "$NC"
    printf "  %bmacOS may prompt for your login password to add the CA to Keychain.%b\n" "$YE" "$NC"
    "$CLOAK_EXE" trust install --yes
else
    printf "\n%b[2/3] Skipping CA trust (as requested)%b\n" "$GY" "$NC"
fi

# --- Step 3: chain to install.sh -----------------------------------------

printf "\n%b[3/3] Running full installer (safe-ordered pf + LaunchAgent + hosts + verify)...%b\n\n" "$CY" "$NC"

if [ ! -x "$INSTALL_SH" ]; then
    chmod +x "$INSTALL_SH" 2>/dev/null || true
fi

"$INSTALL_SH"

# --- Done ---------------------------------------------------------------

printf "\n%b==================================================%b\n" "$GR" "$NC"
printf "%b  cloakline is installed and running.%b\n" "$GR" "$NC"
printf "%b==================================================%b\n\n" "$GR" "$NC"
printf "  Dashboard:   http://127.0.0.1:4001/admin\n"
printf "  Live tail:   ./bin/cloak tail\n"
printf "  Doctor:      ./bin/cloak doctor\n\n"
printf "  Next: add your provider API keys via the dashboard,\n"
printf "        or run ./bin/cloak setup for the interactive wizard.\n\n"
printf "  Uninstall:   ./scripts/uninstall.sh\n\n"
