package ttp

import (
	"fmt"
	"syscall"
)

// MemoryRWX allocates an anonymous mapping, then mprotects it to RWX.
// Writes test bytes to prove access. Does NOT execute any code.
func MemoryRWX(size int) error {
	if size <= 0 {
		size = 4096
	}

	// mmap RW anonymous
	buf, err := syscall.Mmap(
		-1, 0, size,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_ANON|syscall.MAP_PRIVATE,
	)
	if err != nil {
		return fmt.Errorf("mmap: %w", err)
	}

	// write test pattern
	for i := range buf {
		buf[i] = 0xCC
	}

	// mprotect to RWX — this is what Aura detects
	err = syscall.Mprotect(buf, syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC)
	if err != nil {
		_ = syscall.Munmap(buf)
		return fmt.Errorf("mprotect RWX: %w", err)
	}

	// cleanup
	_ = syscall.Munmap(buf)
	return nil
}
