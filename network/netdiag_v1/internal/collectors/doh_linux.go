//go:build linux

package collectors

import (
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// The v1-partial closers for DNS (§4.1): Chrome/Chromium DoH policy,
// on-the-wire DoH/DoT detection from the kernel's own connection table,
// and DNSSEC validation state via the AD flag.

// chromeDoHPolicy reads managed-policy JSON — the enterprise way Chrome
// gets DoH turned on/off. Tri-state string.
func chromeDoHPolicy() string {
	globs := []string{
		"/etc/opt/chrome/policies/managed/*.json",
		"/etc/chromium/policies/managed/*.json",
		"/etc/opt/edge/policies/managed/*.json",
	}
	found := false
	for _, g := range globs {
		matches, _ := filepath.Glob(g)
		for _, m := range matches {
			b, err := os.ReadFile(m)
			if err != nil {
				continue
			}
			found = true
			s := string(b)
			if strings.Contains(s, `"DnsOverHttpsMode"`) &&
				(strings.Contains(s, `"secure"`) || strings.Contains(s, `"automatic"`)) {
				return "enabled"
			}
			if strings.Contains(s, `"DnsOverHttpsMode"`) && strings.Contains(s, `"off"`) {
				return "disabled"
			}
		}
	}
	if found {
		return "unset"
	}
	return "unknown"
}

// dohConnections scans /proc/net/tcp for established connections to known
// DoH (443) / DoT (853) endpoints. Returns the matched targets.
func dohConnections() (doh []string, dot []string) {
	b, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return nil, nil
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 4 || f[3] != "01" { // established only
			continue
		}
		ip, port := hexAddrPort(f[2])
		if ip == "" || !dohProviderIPs[ip] {
			continue
		}
		switch port {
		case 443:
			doh = appendUnique(doh, ip)
		case 853:
			dot = appendUnique(dot, ip)
		}
	}
	return doh, dot
}

func hexAddrPort(s string) (string, int) {
	i := strings.LastIndex(s, ":")
	if i != 8 { // IPv4 form AABBCCDD:PPPP only
		return "", 0
	}
	raw, err := hex.DecodeString(s[:8])
	if err != nil {
		return "", 0
	}
	ip := net.IP{raw[3], raw[2], raw[1], raw[0]} // little-endian
	return ip.String(), hexPort(s)
}
