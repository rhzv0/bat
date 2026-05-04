package ttp

import (
	"syscall"
	"unsafe"
)

var (
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	procSetConsoleTitle = kernel32.NewProc("SetConsoleTitleW")
)

// Masquerade sets the console window title to disguise the agent process.
func Masquerade(name string) error {
	titlePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	procSetConsoleTitle.Call(uintptr(unsafe.Pointer(titlePtr)))
	return nil
}
