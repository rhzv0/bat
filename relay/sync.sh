#!/bin/bash
# sync.sh — Sincroniza relay rodando com versão atual do repo
#
# Uso:
#   ./sync.sh [user@relay-ip] [--key /path/to/key.pem] [--restart-kcc]
#
# Exemplos:
#   ./sync.sh ubuntu@<relay-ip>
#   ./sync.sh ubuntu@<relay-ip> --key /path/to/key.pem
#   ./sync.sh ubuntu@<relay-ip> --key /path/to/key.pem --restart-kcc
#
# Chame após qualquer commit que toca:
#   - relay/kcc-server.py
#   - relay/kcc-build.sh
#   - kperf-qos/      (source do LKM)
#
# Não sincroniza nginx.conf por padrão (mudança de nginx requer cuidado).
# Use --nginx para forçar sincronização do nginx config.
#
# Idempotente: rodar múltiplas vezes é seguro.

set -euo pipefail

RELAY=""
SSH_KEY=""
RESTART_KCC=false
SYNC_NGINX=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --key)          SSH_KEY="$2";     shift 2 ;;
        --restart-kcc)  RESTART_KCC=true; shift   ;;
        --nginx)        SYNC_NGINX=true;  shift   ;;
        *)
            if [[ -z "$RELAY" ]]; then
                RELAY="$1"; shift
            else
                echo "Arg desconhecido: $1"; exit 1
            fi
            ;;
    esac
done

if [[ -z "$RELAY" ]]; then
    echo "Uso: $0 user@relay-ip [--key /path/to/key.pem] [--restart-kcc] [--nginx]"
    exit 1
fi

# Resolve paths relativos ao script (funciona de qualquer CWD)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KPERF_QOS_SRC="${SCRIPT_DIR}/../kperf-qos"

SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10"
[[ -n "$SSH_KEY" ]] && SSH_OPTS="${SSH_OPTS} -i ${SSH_KEY}"

log()  { echo "[SYNC]  $*"; }
ok()   { echo "[OK]    $*"; }
skip() { echo "[SKIP]  $*"; }

ssh_relay() { ssh ${SSH_OPTS} "${RELAY}" "$@"; }
rsync_relay() { rsync -az --delete --rsync-path="sudo rsync" ${SSH_KEY:+-e "ssh -i ${SSH_KEY} -o StrictHostKeyChecking=no"} "$@"; }

# ── 1. Verificar conectividade ────────────────────────────────────────────────
log "Verificando conexão com ${RELAY}..."
ssh_relay 'echo ok' > /dev/null
ok "Conectado"

# ── 2. Sincronizar kperf-qos-src ───────────────────────────────────────────
if [[ -d "${KPERF_QOS_SRC}" ]]; then
    log "Sincronizando kperf-qos-src ($(ls ${KPERF_QOS_SRC}/*.c 2>/dev/null | wc -l) arquivos .c)..."
    rsync_relay "${KPERF_QOS_SRC}/" "${RELAY}:/root/kcc/kperf-qos-src/"
    ok "kperf-qos-src → relay:/root/kcc/kperf-qos-src/"
else
    skip "kperf-qos-src não encontrado em ${KPERF_QOS_SRC}"
fi

# ── 3. Sincronizar kcc-server.py ─────────────────────────────────────────────
log "Sincronizando kcc-server.py..."
rsync_relay "${SCRIPT_DIR}/kcc-server.py" "${RELAY}:/root/kcc/kcc-server.py"
ssh_relay 'sudo chmod 700 /root/kcc/kcc-server.py'
ok "kcc-server.py atualizado"

# ── 4. Sincronizar kcc-build.sh ──────────────────────────────────────────────
log "Sincronizando kcc-build.sh..."
rsync_relay "${SCRIPT_DIR}/kcc-build.sh" "${RELAY}:/root/kcc/kcc-build.sh"
ssh_relay 'sudo chmod 700 /root/kcc/kcc-build.sh'
ok "kcc-build.sh atualizado"

# ── 5. Sincronizar kcc.service (sem restart automático) ──────────────────────
log "Sincronizando kcc.service..."
rsync_relay "${SCRIPT_DIR}/kcc.service" "${RELAY}:/etc/systemd/system/kcc.service"
ssh_relay 'sudo systemctl daemon-reload'
ok "kcc.service atualizado (daemon-reload feito)"

# ── 6. Sincronizar static web (cover page) ───────────────────────────────────
if [[ -d "${SCRIPT_DIR}/static" ]]; then
    log "Sincronizando static web → /var/www/nexus/..."
    ssh_relay 'sudo mkdir -p /var/www/nexus && sudo chown -R www-data:www-data /var/www/nexus'
    rsync_relay "${SCRIPT_DIR}/static/" "${RELAY}:/var/www/nexus/"
    ssh_relay 'sudo chown -R www-data:www-data /var/www/nexus'
    ok "static/ → relay:/var/www/nexus/"
fi

# ── 7. Nginx config (opcional, --nginx) ──────────────────────────────────────
if [[ "$SYNC_NGINX" == true ]]; then
    log "Sincronizando nginx config..."
    rsync_relay "${SCRIPT_DIR}/nginx/bat.conf" "${RELAY}:/etc/nginx/nginx.conf"
    ssh_relay 'sudo nginx -t && sudo systemctl reload nginx'
    ok "nginx config atualizado e recarregado"
else
    skip "nginx (use --nginx para sincronizar)"
fi

# ── 8. Restart KCC se solicitado ─────────────────────────────────────────────
if [[ "$RESTART_KCC" == true ]]; then
    log "Reiniciando kcc.service..."
    ssh_relay 'sudo systemctl restart kcc'
    sleep 2
    STATUS=$(ssh_relay 'sudo systemctl is-active kcc')
    ok "kcc.service: ${STATUS}"
else
    log "AVISO: kcc-server.py atualizado mas serviço não reiniciado."
    log "       Para aplicar: ssh relay 'systemctl restart kcc'"
    log "       Ou use --restart-kcc neste script."
fi

# ── 9. Verificar estado final ─────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════"
echo " Sync COMPLETO → ${RELAY}"
echo "═══════════════════════════════════════════════"
KCC_STATUS=$(ssh_relay 'sudo systemctl is-active kcc' 2>/dev/null || echo "unknown")
NGX_STATUS=$(ssh_relay 'sudo systemctl is-active nginx' 2>/dev/null || echo "unknown")
echo " kcc.service: ${KCC_STATUS}"
echo " nginx:       ${NGX_STATUS}"
echo "═══════════════════════════════════════════════"
