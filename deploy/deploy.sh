#!/usr/bin/env bash
# One-command deployment for policyd on a fresh VPS.
#
# Usage:
#     ./deploy.sh              # deploy (or update) the running stack
#     ./deploy.sh --rollback   # roll back to the previous image tag
#     ./deploy.sh --logs       # tail policyd + caddy logs
#     ./deploy.sh --status     # show current state
#
# Prereqs (install once on the VPS):
#   - Docker Engine + Docker Compose plugin
#   - A domain with an A record pointing to this VPS
#   - Ports 80 and 443 reachable from the internet (for Let's Encrypt)

set -euo pipefail

cd "$(dirname "$0")"

readonly REQUIRED_VARS=(DOMAIN ADMIN_EMAIL ADMIN_PASSWORD_HASH OPENAI_API_KEY)

log()  { printf '\033[1;34m▶\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m✗\033[0m %s\n' "$*" >&2; exit 1; }

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "missing prerequisite: $1"
}

cmd_deploy() {
    require_command docker
    docker compose version >/dev/null 2>&1 || die "docker compose plugin missing"

    if [[ ! -f .env ]]; then
        log "no .env found — copying from .env.example"
        cp .env.example .env
        die "edit deploy/.env with real values, then re-run: ./deploy.sh"
    fi

    # shellcheck disable=SC1091
    set -a; source .env; set +a
    for v in "${REQUIRED_VARS[@]}"; do
        [[ -n "${!v:-}" && "${!v}" != "REPLACE_WITH_BCRYPT_HASH" ]] || die ".env is missing $v"
    done
    [[ "${ADMIN_PASSWORD_HASH}" == \$2* ]] || die "ADMIN_PASSWORD_HASH does not look like a bcrypt hash"

    log "building policyd image"
    docker compose build policyd

    log "starting stack (caddy + policyd)"
    docker compose up -d

    log "waiting for policyd health (up to 60s)"
    for _ in {1..30}; do
        if docker compose ps policyd | grep -q "healthy\|Up"; then
            break
        fi
        sleep 2
    done

    log "verifying HTTPS reachability at https://${DOMAIN}/healthz"
    sleep 5
    if curl -sSf --max-time 20 "https://${DOMAIN}/healthz" >/dev/null; then
        log "deployment succeeded"
        log "public URL: https://${DOMAIN}/"
    else
        warn "healthz probe failed — TLS may still be provisioning. Try again in 60s."
        warn "run: ./deploy.sh --logs"
    fi
}

cmd_rollback() {
    require_command docker
    log "rolling back to previous image (using local docker image cache)"
    docker compose down
    docker compose up -d
    log "rollback complete"
}

cmd_logs() {
    docker compose logs --tail=200 -f
}

cmd_status() {
    docker compose ps
    echo
    log "recent policyd log lines:"
    docker compose logs --tail=20 policyd || true
}

case "${1:-deploy}" in
    deploy|"")   cmd_deploy   ;;
    --rollback)  cmd_rollback ;;
    --logs)      cmd_logs     ;;
    --status)    cmd_status   ;;
    *)           die "unknown command: $1" ;;
esac
