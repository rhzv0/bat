package ttp

import (
	"os"
	"os/exec"
	"strings"

	"core/mon/internal/protocol"
)

// CollectEnvFingerprint gathers Windows environment details.
// Field mapping to shared EnvReport:
//   KernelVersion  = Windows build string (e.g. "10.0.19041")
//   Distro         = ProductName from registry (e.g. "Windows Server 2022")
//   InitSystem     = "windows"
//   Container      = false (no container detection on Windows)
//   PtraceScope    = 0 if admin, 1 if limited user
//   SELinuxMode    = "DOMAIN\User@COMPUTERNAME" for operator context
//   TargetComm     = architecture (amd64/arm64)
func CollectEnvFingerprint(_ []string) protocol.EnvReport {
	r := protocol.EnvReport{
		Container:  false,
		InitSystem: "windows",
	}

	// Product name from registry
	r.Distro = winProductName()

	// Build number from registry
	r.KernelVersion = winBuildNumber()

	// Admin indicator: 0 = admin, 1 = limited
	if isAdmin() {
		r.PtraceScope = 0
	} else {
		r.PtraceScope = 1
	}

	// Operator context: DOMAIN\User@COMPUTERNAME
	user := os.Getenv("USERNAME")
	domain := os.Getenv("USERDOMAIN")
	computer := os.Getenv("COMPUTERNAME")
	if user != "" {
		r.SELinuxMode = domain + `\` + user + "@" + computer
	}

	// Architecture
	r.TargetComm = os.Getenv("PROCESSOR_ARCHITECTURE")

	return r
}

// winProductName reads the Windows product name from the registry.
func winProductName() string {
	out, err := exec.Command("reg", "query",
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`,
		"/v", "ProductName").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "ProductName") {
			parts := strings.SplitN(line, "REG_SZ", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// winBuildNumber reads the CurrentBuild value from the registry.
func winBuildNumber() string {
	out, err := exec.Command("reg", "query",
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`,
		"/v", "CurrentBuild").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "CurrentBuild") {
			parts := strings.SplitN(line, "REG_SZ", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// isAdmin attempts to open a privileged device handle as admin check.
func isAdmin() bool {
	f, err := os.Open(`\\.\PHYSICALDRIVE0`)
	if err == nil {
		f.Close()
		return true
	}
	return false
}
