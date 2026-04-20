#!/bin/bash
# sync.sh Sync a running relay with the current repo state
#
# Usage:
# ./sync.sh [user@relay-ip] [--key /path/to/key.pem] [--restart-kcc] [--nginx] [--tg]
#
# Prerequisite: build.env filled in (CDN_DOMAIN is used to substitute __CDN_DOMAIN__
# in relay/static/ delivery scripts before rsync).
#
# Call after any commit touching:
# - relay/kcc-server.py
# - relay/kcc-build.sh
# - kperf-qos/ (LKM source)
#
# Does not sync nginx.conf by default. Use --nginx to force.
# Idempotent: safe to run multiple times.

set -euo pipefail

RELAY=""
SSH_KEY=""
RESTART_KCC=false
SYNC_NGINX=false
SYNC_TG=false

while [[ $# -gt 0 ]]; do
 case "$1" in
 --key) SSH_KEY="$2"; shift 2 ;;
 --restart-kcc)  RESTART_KCC=true; shift ;;
 --nginx) SYNC_NGINX=true;  shift ;;
 --tg) SYNC_TG=true; shift ;;
 *)
 if [[ -z "$RELAY" ]]; then
 RELAY="$1"; shift
 else
 echo "Unknown argument: $1"; exit 1
 fi
 ;;
 esac
done

if [[ -z "$RELAY" ]]; then
 echo "Usage: $0 user@relay-ip [--key /path/to/key.pem] [--restart-kcc] [--nginx] [--tg]"
 exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${SCRIPT_DIR}/.."
ENV_FILE="${REPO_ROOT}/build.env"

# Source build.env for CDN_DOMAIN, TG_TOKEN, TG_CHAT_ID
if [[ -f "$ENV_FILE" ]]; then
 # shellcheck source=/dev/null
 source "$ENV_FILE"
fi

CDN_DOMAIN="${CDN_DOMAIN:-}"
KPERF_QOS_SRC="${SCRIPT_DIR}/../kperf-qos"

SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10"
[[ -n "$SSH_KEY" ]] && SSH_OPTS="${SSH_OPTS} -i ${SSH_KEY}"

log()  { echo "[SYNC]  $*"; }
ok() { echo "[OK] $*"; }
skip() { echo "[SKIP]  $*"; }

ssh_relay() { ssh ${SSH_OPTS} "${RELAY}" "$@"; }
rsync_relay() { rsync -az --delete --exclude='agents/' --rsync-path="sudo rsync" ${SSH_KEY:+-e "ssh -i ${SSH_KEY} -o StrictHostKeyChecking=no"} "$@"; }

# 1. Connectivity check 
log "Checking connection to ${RELAY}..."
ssh_relay 'echo ok' > /dev/null
ok "Connected"

# 2. kperf-qos-src 
if [[ -d "${KPERF_QOS_SRC}" ]]; then
 log "Syncing kperf-qos-src ($(ls ${KPERF_QOS_SRC}/*.c 2>/dev/null | wc -l) .c files)..."
 rsync_relay "${KPERF_QOS_SRC}/" "${RELAY}:/root/kcc/kperf-qos-src/"
 ok "kperf-qos-src → relay:/root/kcc/kperf-qos-src/"
else
 skip "kperf-qos-src not found at ${KPERF_QOS_SRC}"
fi

# 3. kcc-server.py 
log "Syncing kcc-server.py..."
rsync_relay "${SCRIPT_DIR}/kcc-server.py" "${RELAY}:/root/kcc/kcc-server.py"
ssh_relay 'sudo chmod 700 /root/kcc/kcc-server.py'
ok "kcc-server.py updated"

# 4. kcc-build.sh 
log "Syncing kcc-build.sh..."
rsync_relay "${SCRIPT_DIR}/kcc-build.sh" "${RELAY}:/root/kcc/kcc-build.sh"
ssh_relay 'sudo chmod 700 /root/kcc/kcc-build.sh'
ok "kcc-build.sh updated"

# 5. kcc.service 
log "Syncing kcc.service..."
rsync_relay "${SCRIPT_DIR}/kcc.service" "${RELAY}:/etc/systemd/system/kcc.service"
ssh_relay 'sudo systemctl daemon-reload'
ok "kcc.service updated (daemon-reload done)"

# 5b. delivery-alert.sh 
if [[ -f "${SCRIPT_DIR}/delivery-alert.sh" ]]; then
 log "Syncing delivery-alert.sh..."
 rsync_relay "${SCRIPT_DIR}/delivery-alert.sh" "${RELAY}:/opt/delivery-alert.sh"
 ssh_relay 'sudo chmod 700 /opt/delivery-alert.sh && sudo systemctl restart delivery-alert 2>/dev/null || true'
 ok "delivery-alert.sh → /opt/delivery-alert.sh"
fi

# 5c. Telegram credentials (--tg) 
if [[ "$SYNC_TG" == true ]]; then
 if [[ -z "${TG_TOKEN:-}" || -z "${TG_CHAT_ID:-}" ]]; then
 echo "[ERROR] --tg requires TG_TOKEN and TG_CHAT_ID. Source build.env first or set in env."
 exit 1
 fi
 log "Syncing /etc/bat/tg.env on relay..."
 ssh_relay "sudo mkdir -p /etc/bat && sudo chmod 700 /etc/bat"
 ssh_relay "sudo bash -c 'echo TG_TOKEN=${TG_TOKEN} > /etc/bat/tg.env && echo TG_CHAT_ID=${TG_CHAT_ID} >> /etc/bat/tg.env && chmod 600 /etc/bat/tg.env'"
 ssh_relay 'sudo systemctl restart delivery-alert 2>/dev/null || true'
 ok "/etc/bat/tg.env updated + delivery-alert restarted"
else
 skip "Telegram creds (use --tg to sync)"
fi

# 6. Static web (cover page + delivery vectors) 
if [[ -d "${SCRIPT_DIR}/static" ]]; then
 log "Syncing static web → /var/www/nexus/..."

 # Substitute __CDN_DOMAIN__ with the real domain before rsync
 if [[ -n "$CDN_DOMAIN" ]]; then
 STATIC_TMP=$(mktemp -d)
 trap 'rm -rf "$STATIC_TMP"' EXIT
 cp -a "${SCRIPT_DIR}/static/." "$STATIC_TMP/"
 find "$STATIC_TMP" -type f -exec sed -i "s/__CDN_DOMAIN__/${CDN_DOMAIN}/g" {} +
 log "  __CDN_DOMAIN__ → ${CDN_DOMAIN}"
 SYNC_SRC="$STATIC_TMP/"
 else
 log "  WARNING: CDN_DOMAIN not set syncing __CDN_DOMAIN__ placeholder literally"
 SYNC_SRC="${SCRIPT_DIR}/static/"
 fi

 ssh_relay 'sudo mkdir -p /var/www/nexus && sudo chown -R www-data:www-data /var/www/nexus'
 rsync_relay "$SYNC_SRC" "${RELAY}:/var/www/nexus/"
 ssh_relay 'sudo chown -R www-data:www-data /var/www/nexus'
 ok "static/ → relay:/var/www/nexus/"
fi

# 7. Nginx config (--nginx to force) 
if [[ "$SYNC_NGINX" == true ]]; then
 log "Syncing nginx config..."
 rsync_relay "${SCRIPT_DIR}/nginx/bat.conf" "${RELAY}:/etc/nginx/nginx.conf"
 ssh_relay 'sudo nginx -t && sudo systemctl reload nginx'
 ok "nginx config updated and reloaded"
else
 skip "nginx (use --nginx to sync)"
fi

# 8. Restart KCC if requested 
if [[ "$RESTART_KCC" == true ]]; then
 log "Restarting kcc.service..."
 ssh_relay 'sudo systemctl restart kcc'
 sleep 2
 STATUS=$(ssh_relay 'sudo systemctl is-active kcc')
 ok "kcc.service: ${STATUS}"
else
 log "NOTE: kcc-server.py updated but service not restarted."
 log " To apply: ssh relay 'systemctl restart kcc'"
 log " Or use --restart-kcc with this script."
fi

# 9. Final status 
echo ""
echo "═══════════════════════════════════════════════"
echo " Sync COMPLETE → ${RELAY}"
echo "═══════════════════════════════════════════════"
KCC_STATUS=$(ssh_relay 'sudo systemctl is-active kcc' 2>/dev/null || echo "unknown")
NGX_STATUS=$(ssh_relay 'sudo systemctl is-active nginx' 2>/dev/null || echo "unknown")
echo " kcc.service: ${KCC_STATUS}"
echo " nginx: ${NGX_STATUS}"
echo "═══════════════════════════════════════════════"
