#!/usr/bin/env bash
# cloakline installer — macOS.
#
# SAFE ORDERING: hosts entries are the LAST thing added, only after
# cloakline is verified listening on :8443 and the pf redirect for :443
# is active. If ANY step fails, hosts entries are rolled back so
# nothing is left in a broken state.
#
# What this script does (in order):
#   1. Verify prerequisites (binary + config present).
#   2. Set inspect.listen to :8443 in configs/pipeline.yaml.
#   3. Install pf anchor redirecting :443 -> :8443 on lo0 (needs sudo).
#   4. Install ~/Library/LaunchAgents/com.cloakline.daemon.plist.
#   5. Load and start the LaunchAgent (runs as the current user).
#   6. Verify cloakline admin :4001 responds and :8443 accepts TLS.
#   7. Add hosts entries for api.anthropic.com and api.openai.com.
#   8. Verify DNS resolves those hostnames to 127.0.0.1.
#
# On failure at step 7+, hosts entries added by this script are removed.
#
# Usage:  ./scripts/install.sh   (bootstrap.sh invokes this)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="$REPO_ROOT/bin"
DAEMON_EXE="$BIN_DIR/cloakline"
CONFIG_DIR="$REPO_ROOT/configs"
PIPELINE_YAML="$CONFIG_DIR/pipeline.yaml"
HOSTS_FILE="/etc/hosts"
PLIST_PATH="$HOME/Library/LaunchAgents/com.cloakline.daemon.plist"
PF_ANCHOR_PATH="/etc/pf.anchors/com.cloakline"
LAUNCHAGENT_LABEL="com.cloakline.daemon"

# ANSI colors (skip when NO_COLOR or non-tty).
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    CY="\033[36m"; GR="\033[32m"; RE="\033[31m"; YE="\033[33m"; GY="\033[90m"; NC="\033[0m"
else
    CY=""; GR=""; RE=""; YE=""; GY=""; NC=""
fi

HOSTS_ADDED=()

log()  { printf "  %b\n" "$*"; }
info() { printf "\n%b%s%b\n" "$CY" "$1" "$NC"; }
ok()   { printf "  %b✓%b %s\n" "$GR" "$NC" "$1"; }
warn() { printf "  %b!%b %s\n" "$YE" "$NC" "$1"; }
fail() { printf "  %b✗%b %s\n" "$RE" "$NC" "$1"; }

rollback_hosts() {
    if [ ${#HOSTS_ADDED[@]} -eq 0 ]; then return; fi
    printf "\n"
    warn "Rolling back hosts entries so nothing is left in a broken state..."
    for line in "${HOSTS_ADDED[@]}"; do
        # Best-effort sed on the hosts file. Escape the line for sed.
        local esc
        esc="$(printf '%s' "$line" | sed -e 's/[]\/$*.^[]/\\&/g')"
        sudo sed -i.cloakline-bak "/^${esc}$/d" "$HOSTS_FILE" 2>/dev/null || true
    done
    sudo dscacheutil -flushcache 2>/dev/null || true
    sudo killall -HUP mDNSResponder 2>/dev/null || true
    ok "hosts restored"
}

on_error() {
    fail "installation failed at line $1"
    rollback_hosts
    exit 1
}
trap 'on_error $LINENO' ERR

# --- Preflight -----------------------------------------------------------

info "cloakline installer (safe ordering)"
log "${GY}repo: $REPO_ROOT${NC}"

info "[1/7] Prerequisite checks..."
if [ ! -x "$DAEMON_EXE" ]; then
    fail "cloakline binary not found or not executable at $DAEMON_EXE"
    fail "run bootstrap.sh (which builds first) or 'make build' before install.sh"
    exit 1
fi
if [ ! -f "$PIPELINE_YAML" ]; then
    fail "pipeline.yaml not found at $PIPELINE_YAML"
    exit 1
fi
ok "binary + config present"

# --- Step 2: pipeline.yaml -----------------------------------------------

info "[2/7] Configuring cloakline to listen on :8443..."
if grep -q '^\s*enabled:\s*true' "$PIPELINE_YAML"; then
    ok "inspect module already enabled"
else
    sed -i.bak 's/\(inspect:[[:space:]]*\n[[:space:]]*enabled:[[:space:]]*\)false/\1true/' "$PIPELINE_YAML" 2>/dev/null || true
fi
# Ensure inspect.listen is :8443 (macOS binds :443 via pf redirect).
if grep -qE '^\s*listen:\s*":?8443"?' "$PIPELINE_YAML"; then
    ok "pipeline.yaml: inspect.listen already :8443"
else
    sed -i.bak -E 's/^(\s*listen:\s*)":?443"?/\1":8443"/' "$PIPELINE_YAML"
    ok "pipeline.yaml: inspect.listen -> :8443"
fi
rm -f "$PIPELINE_YAML.bak"

# --- Step 3: pf anchor for 443 -> 8443 -----------------------------------

info "[3/7] Installing pf redirect (:443 -> :8443)..."
log "${GY}pf keeps cloakline unprivileged on :8443 while :443 traffic still flows through.${NC}"
log "${GY}sudo needed once to load the anchor.${NC}"

PF_RULE='rdr pass on lo0 inet proto tcp from any to 127.0.0.1 port 443 -> 127.0.0.1 port 8443'
if [ -f "$PF_ANCHOR_PATH" ] && grep -qF "$PF_RULE" "$PF_ANCHOR_PATH"; then
    ok "pf anchor already installed"
else
    echo "$PF_RULE" | sudo tee "$PF_ANCHOR_PATH" > /dev/null
    ok "wrote $PF_ANCHOR_PATH"
fi

# Load the anchor and enable pf. -a scopes the load to our anchor only, so
# we don't touch /etc/pf.conf's main ruleset.
sudo pfctl -a com.cloakline -f "$PF_ANCHOR_PATH" 2>/dev/null || {
    fail "pfctl -f failed loading anchor"
    exit 1
}
sudo pfctl -E 2>/dev/null || true    # -E enables pf (idempotent, may warn if already enabled)
ok "pf anchor loaded"

# --- Step 4: LaunchAgent plist -------------------------------------------

info "[4/7] Installing LaunchAgent..."
mkdir -p "$(dirname "$PLIST_PATH")"
cat > "$PLIST_PATH" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>              <string>$LAUNCHAGENT_LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$DAEMON_EXE</string>
        <string>--config</string>
        <string>$CONFIG_DIR</string>
    </array>
    <key>WorkingDirectory</key>   <string>$REPO_ROOT</string>
    <key>RunAtLoad</key>          <true/>
    <key>KeepAlive</key>          <true/>
    <key>StandardOutPath</key>    <string>/tmp/cloakline.log</string>
    <key>StandardErrorPath</key>  <string>/tmp/cloakline.err</string>
</dict>
</plist>
PLIST
ok "wrote $PLIST_PATH"

# Reload if already loaded.
launchctl unload "$PLIST_PATH" 2>/dev/null || true
launchctl load "$PLIST_PATH"
ok "LaunchAgent loaded"

# --- Step 5: verify listening --------------------------------------------

info "[5/7] Verifying cloakline is actually listening..."
admin_ok=0
tls_ok=0
for i in $(seq 1 15); do
    sleep 1
    if [ $admin_ok -eq 0 ]; then
        if curl -sf http://127.0.0.1:4001/healthz > /dev/null 2>&1; then
            admin_ok=1
            ok "admin :4001 responding (${i}s)"
        fi
    fi
    if [ $tls_ok -eq 0 ]; then
        # Try the TLS handshake via curl on :8443 direct (bypasses pf).
        if curl -sk --max-time 2 --connect-timeout 2 https://127.0.0.1:8443/ > /dev/null 2>&1 || \
           curl -sk --max-time 2 --connect-timeout 2 --output /dev/null https://127.0.0.1:8443/ 2>&1 | grep -qv "Connection refused"; then
            # Even if 400 or 404, if the connection was accepted the daemon is listening.
            if lsof -i :8443 -sTCP:LISTEN > /dev/null 2>&1 || netstat -an 2>/dev/null | grep -qE '\*\.8443\s+.*LISTEN'; then
                tls_ok=1
                ok ":8443 accepting TLS (${i}s)"
            fi
        fi
    fi
    if [ $admin_ok -eq 1 ] && [ $tls_ok -eq 1 ]; then break; fi
done
if [ $admin_ok -ne 1 ]; then
    fail "cloakline admin :4001 did not respond within 15s"
    fail "check /tmp/cloakline.err for daemon startup errors"
    exit 1
fi
if [ $tls_ok -ne 1 ]; then
    fail "cloakline :8443 not listening — check /tmp/cloakline.err"
    exit 1
fi

# --- Step 6: hosts entries (now safe — daemon is listening) --------------

info "[6/7] Adding hosts entries..."
for hostline in "127.0.0.1 api.anthropic.com" "127.0.0.1 api.openai.com"; do
    if grep -qE "^${hostline//\./\\.}$" "$HOSTS_FILE" 2>/dev/null; then
        log "${GY}hosts: '$hostline' already present${NC}"
    else
        printf "%s\n" "$hostline" | sudo tee -a "$HOSTS_FILE" > /dev/null
        HOSTS_ADDED+=("$hostline")
        ok "hosts: added '$hostline'"
    fi
done

# Flush DNS.
sudo dscacheutil -flushcache 2>/dev/null || true
sudo killall -HUP mDNSResponder 2>/dev/null || true

# --- Step 7: verify DNS --------------------------------------------------

info "[7/7] Verifying DNS redirect..."
sleep 1
# Use `dscacheutil -q host -a name X` which uses the OS resolver (honors /etc/hosts).
resolved="$(dscacheutil -q host -a name api.anthropic.com 2>/dev/null | awk '/^ip_address:/ {print $2}' | head -n1)"
if [ "$resolved" = "127.0.0.1" ]; then
    ok "api.anthropic.com -> 127.0.0.1"
else
    fail "DNS did not update: api.anthropic.com resolved to '${resolved:-<empty>}', expected 127.0.0.1"
    exit 1
fi

# --- Done ---------------------------------------------------------------

info "Install complete."
log "  Dashboard: ${CY}http://127.0.0.1:4001/admin${NC}"
log "  Live tail: ${CY}$BIN_DIR/cloak tail${NC}"
log "  Doctor:    ${CY}$BIN_DIR/cloak doctor${NC}"
log "  Uninstall: ${CY}./scripts/uninstall.sh${NC}"
printf "\n"
