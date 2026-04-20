package ttp

import (
	"bytes"
	"fmt"
	"os/exec"
)

// ShellExec runs an arbitrary command via sh -c and returns combined output.
func ShellExec(cmd string) (string, error) {
	if cmd == "" {
		return "", fmt.Errorf("empty command")
	}
	var buf bytes.Buffer
	c := exec.Command("sh", "-c", cmd)
	c.Stdout = &buf
	c.Stderr = &buf
	if err := c.Run(); err != nil {
		// Return output even on non-zero exit   useful for recon
		if buf.Len() > 0 {
			return buf.String(), nil
		}
		return "", err
	}
	return buf.String(), nil
}
