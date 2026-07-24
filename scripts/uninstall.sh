#!/usr/bin/env bash
# cloakline uninstaller — macOS.
#
# Reverses everything install.sh did:
#   1. Stops and unloads the LaunchAgent.
#   2. Kills any running cloakline process.
#   3. Removes the pf anchor and reloads pf.
#   4. Removes hosts entries and flushes DNS.
#   5. Reverts inspect.listen back to :8443 (safe default).
#   6. Removes the CA from Keychain (via cloak trust remove).
#
# Data left in place (delete manually if you want a full wipe):
#   - bin/cloak, bin/cloakline
#   - $HOME/Library/Application Support/cloakline (Keychain index file)
#   - $HOME/Library/Application Support/cloakline (CA files, prefs.key)
#
# Usage:  ./scripts/uninstall.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="$REPO_ROOT/bin"
CLOAK_EXE="$BIN_DIR/cloak"
PIPELINE_YAML="$REPO_ROOT/configs/pipeline.yaml"
HOSTS_FILE="/etc/hosts"
PLIST_PATH="$HOME/Library/LaunchAgents/com.cloakline.daemon.plist"
PF_ANCHOR_PATH="/etc/pf.anchors/com.cloakline"
LAUNCHAGENT_LABEL="com.cloakline.daemon"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    CY="\033[36m"; GR="\033[32m"; YE="\033[33m"; GY="\033[90m"; NC="\033[0m"
else
    CY=""; GR=""; YE=""; GY=""; NC=""
fi

info() { printf "\n%b%s%b\n" "$CY" "$1" "$NC"; }
ok()   { printf "  %b✓%b %s\n" "$GR" "$NC" "$1"; }
skip() { printf "  %b·%b %s\n" "$GY" "$NC" "$1"; }
warn() { printf "  %b!%b %s\n" "$YE" "$NC" "$1"; }

info "cloakline uninstaller"

# --- Step 1: LaunchAgent -------------------------------------------------

info "[1/6] Unloading LaunchAgent..."
if [ -f "$PLIST_PATH" ]; then
    launchctl unload "$PLIST_PATH" 2>/dev/null || true
    rm -f "$PLIST_PATH"
    ok "LaunchAgent removed"
else
    skip "no LaunchAgent found"
fi

# --- Step 2: kill any stragglers -----------------------------------------

info "[2/6] Stopping any running cloakline process..."
if pkill -x cloakline 2>/dev/null; then
    ok "sent SIGTERM to cloakline"
else
    skip "no running cloakline process"
fi

# --- Step 3: pf anchor ---------------------------------------------------

info "[3/6] Removing pf anchor (:443 -> :8443 redirect)..."
if [ -f "$PF_ANCHOR_PATH" ]; then
    # Flush the anchor rules and remove the anchor file.
    sudo pfctl -a com.cloakline -F all 2>/dev/null || true
    sudo rm -f "$PF_ANCHOR_PATH"
    ok "pf anchor removed"
else
    skip "no pf anchor found"
fi

# --- Step 4: hosts entries ----------------------------------------------

info "[4/6] Removing hosts entries..."
removed=0
for hostline in "127.0.0.1 api.anthropic.com" "127.0.0.1 api.openai.com"; do
    if grep -qE "^${hostline//\./\\.}$" "$HOSTS_FILE" 2>/dev/null; then
        esc="$(printf '%s' "$hostline" | sed -e 's/[]\/$*.^[]/\\&/g')"
        sudo sed -i.cloakline-bak "/^${esc}$/d" "$HOSTS_FILE"
        removed=$((removed + 1))
    fi
done
sudo rm -f "${HOSTS_FILE}.cloakline-bak" 2>/dev/null || true
if [ $removed -gt 0 ]; then
    sudo dscacheutil -flushcache 2>/dev/null || true
    sudo killall -HUP mDNSResponder 2>/dev/null || true
    ok "removed $removed hosts entries + flushed DNS"
else
    skip "no cloakline hosts entries found"
fi

# --- Step 5: pipeline.yaml reset ----------------------------------------

info "[5/6] Reverting inspect.listen to safe default..."
if [ -f "$PIPELINE_YAML" ]; then
    # If someone changed listen back to :443 on macOS somehow, put it back.
    if grep -qE '^\s*listen:\s*":?443"?' "$PIPELINE_YAML"; then
        sed -i.bak -E 's/^(\s*listen:\s*)":?443"?/\1":8443"/' "$PIPELINE_YAML"
        rm -f "$PIPELINE_YAML.bak"
        ok "inspect.listen -> :8443"
    else
        skip "inspect.listen already :8443 (or absent)"
    fi
fi

# --- Step 6: CA removal --------------------------------------------------

info "[6/6] Removing local inspection CA from Keychain..."
if [ -x "$CLOAK_EXE" ]; then
    "$CLOAK_EXE" trust remove --yes 2>/dev/null || warn "CA removal failed — remove manually from Keychain Access.app"
    ok "CA removal requested (Keychain may ask for your password)"
else
    warn "cloak binary not found — skip CA removal; remove manually from Keychain Access.app"
fi

info "Uninstall complete."
printf "  Binaries left in: %b%s%b\n" "$CY" "$BIN_DIR" "$NC"
printf "  App data left in: %b\$HOME/Library/Application Support/cloakline%b\n" "$CY" "$NC"
printf "  Delete either manually for a full wipe.\n\n"
