package ttp

import (
	"fmt"
	"syscall"
	"unsafe"

	"core/mon/internal/obf"
)

const prSetName = 15

// DefaultMasqName returns the obfuscated default masquerade name.
func DefaultMasqName() string { return obf.D(obf.Masq) }

// Masquerade changes the process comm name visible in ps/top.
func Masquerade(name string) error {
	if len(name) > 15 {
		name = name[:15]
	}
	b := append([]byte(name), 0)
	_, _, errno := syscall.RawSyscall(
		syscall.SYS_PRCTL,
		prSetName,
		uintptr(unsafe.Pointer(&b[0])),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("prctl PR_SET_NAME: %w", errno)
	}
	return nil
}
