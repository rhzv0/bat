#!/usr/bin/env bash
# delivery-alert   monitora /var/log/nginx/delivery.log e notifica Telegram
# em cada download bem-sucedido (HTTP 200) nos honey endpoints.
#
# Log format esperado (nginx formato "delivery"):
#   <real_ip> [timestamp] "METHOD /path HTTP/x" status bytes "UA" edge=<cf_edge_ip>
#
# Instalação: ver delivery-alert.service
# Credenciais: TG_TOKEN e TG_CHAT_ID injetados via EnvironmentFile no serviço

LOG="/var/log/nginx/delivery.log"

_tg() {
    local msg="$1"
    [[ -z "${TG_TOKEN:-}" || -z "${TG_CHAT_ID:-}" ]] && return
    curl -s -m 8 -X POST \
        "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
        -d "chat_id=${TG_CHAT_ID}" \
        --data-urlencode "text=${msg}" \
        > /dev/null 2>&1 &
}

# Esperar log existir
until [[ -f "$LOG" ]]; do sleep 5; done

tail -F "$LOG" | while IFS= read -r line; do
    # Formato: <real_ip> [date time] "METHOD /path HTTP/x" status bytes "UA" edge=<cf_edge>
    # Campos awk (timestamp tem espaço   $2=date $3=time+]):
    #   $1=ip $2=[date $3=time] $4="METHOD $5=/path $6=HTTP/x" $7=status $8=bytes $9="UA" $10=edge=IP

    status=$(echo "$line" | awk '{print $7}')
    [[ "$status" != "200" ]] && continue

    real_ip=$(echo "$line" | awk '{print $1}')
    timestamp=$(echo "$line" | awk '{print $2" "$3}' | tr -d '[]')
    path=$(echo "$line" | awk -F'"' '{print $2}' | awk '{print $2}')
    bytes=$(echo "$line" | awk '{print $8}')
    ua=$(echo "$line" | awk -F'"' '{print $4}')
    edge=$(echo "$line" | awk '{print $NF}' | cut -d= -f2)

    # Determinar arch pela UA
    arch="x86_64"
    echo "$ua" | grep -qiE "aarch64|arm64" && arch="arm64"

    msg="HONEYPOT HIT
IP: ${real_ip}
Time: ${timestamp}
Path: ${path}
Arch: ${arch}
Size: ${bytes}B
UA: ${ua:0:80}
Edge: ${edge}"

    _tg "$msg"
done
