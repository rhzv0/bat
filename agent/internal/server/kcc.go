package server

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// KCCAddr is the local address of the KCC server, reachable via SSH -L tunnel.
// batrev alias: -L 8444:localhost:8444 forwards local:8444 → relay's localhost:8444.
const KCCAddr = "127.0.0.1:8444"

// KCCRequest is sent to kcc-server.py.
type KCCRequest struct {
	KernelVersion string `json:"kernel_version"`
	Arch          string `json:"arch"`
	ConfigHash    string `json:"config_hash"`
}

// KCCResponse is returned by kcc-server.py.
type KCCResponse struct {
	Status   string `json:"status"`
	KOB64    string `json:"ko_b64"`    // base64-encoded .ko bytes
	KOSha256 string `json:"ko_sha256"` // hex SHA-256 of raw .ko
	Cached   bool   `json:"cached"`
	Msg      string `json:"msg"` // error message when status != "ok"
}

// CallKCC sends a compile request to the KCC server and returns the result.
// Blocks until compilation completes (up to 300s for cache miss).
// kernelVersion: e.g. "6.1.0-44-cloud-amd64"
// arch: kernel arch string, e.g. "x86_64" or "arm64" (use GoArchToKernelArch)
// configHash: pass "nohash" when /proc/config.gz is not available
func CallKCC(kernelVersion, arch, configHash string) (*KCCResponse, error) {
	req := KCCRequest{
		KernelVersion: kernelVersion,
		Arch:          arch,
		ConfigHash:    configHash,
	}
	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	// TCP connect   must succeed before proceeding
	conn, err := net.DialTimeout("tcp", KCCAddr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial KCC %s: %w", KCCAddr, err)
	}
	defer conn.Close()

	// Deadline: 305s   extra 5s buffer over kcc-server's 300s build timeout
	conn.SetDeadline(time.Now().Add(305 * time.Second)) //nolint:errcheck

	// Send request
	if _, err := conn.Write(data); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}
	// Signal EOF so kcc-server's reader.read(-1) returns
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.CloseWrite() //nolint:errcheck
	}

	// Read response
	var resp KCCResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &resp, nil
}

// GoArchToKernelArch converts Go's runtime.GOARCH to the kernel/kbuild ARCH string.
func GoArchToKernelArch(goarch string) string {
	switch goarch {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "arm64"
	case "386":
		return "i386"
	default:
		return goarch
	}
}
