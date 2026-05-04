package ttp

import (
	"os/exec"
	"syscall"
)

// ShellExec runs a command via cmd.exe /C and returns combined output.
func ShellExec(command string) (string, error) {
	cmd := exec.Command("cmd", "/C", command)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	return string(out), err
}
