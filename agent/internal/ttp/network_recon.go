package ttp

// network_recon.go   TTP 20: network discovery via ARP table + port scan
//
// ATT&CK: T1018 (Remote System Discovery) + T1046 (Network Service Discovery)
//
// Steps:
//  1. Parse /proc/net/arp for resolved ARP entries (live hosts on LAN)
//  2. TCP connect-probe :22 on each discovered host (no raw SYN   just connect())
//  3. Return formatted report for C2 exfiltration
//
// Passive footprint: only reads /proc/net/arp + opens TCP connections to :22.
// No ICMP, no raw sockets, no broadcast   blends into normal SSH traffic.

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// NetworkRecon discovers live hosts on the local network and probes :22.
func NetworkRecon() (string, error) {
	hosts, err := parseARPTable()
	if err != nil {
		return "", fmt.Errorf("arp table: %w", err)
	}
	if len(hosts) == 0 {
		return "network_recon: arp table empty (no resolved hosts)", nil
	}

	var lines []string
	for _, ip := range hosts {
		status := probeTCP(ip, 22, 2*time.Second)
		lines = append(lines, fmt.Sprintf("%s:22 %s", ip, status))
	}
	return fmt.Sprintf("network_recon: %d hosts in ARP table\n%s",
		len(hosts), strings.Join(lines, "\n")), nil
}

// parseARPTable reads /proc/net/arp and returns IPs of resolved ARP entries.
// Skips incomplete entries (flags=0x0) that have no confirmed MAC.
func parseARPTable() ([]string, error) {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	var ips []string
	for i, line := range strings.Split(string(data), "\n") {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue // skip header and blank lines
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// field[2] = HW flags: 0x0 = incomplete, 0x2 = complete
		if fields[2] == "0x0" {
			continue
		}
		if ip := net.ParseIP(fields[0]); ip != nil {
			ips = append(ips, fields[0])
		}
	}
	return ips, nil
}

// probeTCP attempts a TCP connection to host:port and returns "open" or "closed".
func probeTCP(host string, port int, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return "closed"
	}
	conn.Close()
	return "open"
}
