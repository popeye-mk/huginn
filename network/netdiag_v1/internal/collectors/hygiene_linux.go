//go:build linux

package collectors

// Linux hygiene reads (§12): listening ports from the kernel's own tables,
// plus the local name-resolution services that create the same poisoning
// surface LLMNR/NetBIOS do on Windows (Avahi/mDNS, systemd-resolved's LLMNR).

import (
	"context"
	"os"
	"strconv"
	"strings"

	"netdiag/internal/run"
	"netdiag/internal/schema"
)

type hygieneCollector struct{}

func (hygieneCollector) Name() string      { return "hygiene" }
func (hygieneCollector) Privilege() string { return schema.PrivUnprivileged }

func (hygieneCollector) Collect(_ context.Context) (map[string]any, error) {
	listening := linuxListeningPorts()

	poisoning := map[string]bool{}
	// systemd-resolved: LLMNR=yes|resolve|no in resolved.conf (default yes).
	if b, err := os.ReadFile("/etc/systemd/resolved.conf"); err == nil {
		llmnr := true // upstream default
		for _, line := range strings.Split(string(b), "\n") {
			t := strings.TrimSpace(strings.ToLower(line))
			if strings.HasPrefix(t, "llmnr=") {
				v := strings.TrimSpace(strings.TrimPrefix(t, "llmnr="))
				llmnr = v != "no" && v != "false"
			}
		}
		poisoning["LLMNR"] = llmnr
	}
	// Avahi/mDNS: a running daemon answers .local queries for this host.
	for _, p := range []string{"/run/avahi-daemon/pid", "/var/run/avahi-daemon/pid"} {
		if _, err := os.Stat(p); err == nil {
			poisoning["mDNS"] = true
			break
		}
	}
	if _, ok := poisoning["mDNS"]; !ok {
		// Port 5353 open is the same exposure by another route.
		for _, port := range listening {
			if port == 5353 {
				poisoning["mDNS"] = true
			}
		}
	}
	// NetBIOS name service is Samba's nmbd on 137/udp.
	for _, port := range listening {
		if port == 137 || port == 139 {
			poisoning["NetBIOS-NS"] = true
		}
	}

	// SMBv1: Samba's "min protocol". Absent config means the distro default,
	// which on any current Samba is already above SMB1 — so an absent answer
	// is left absent rather than guessed.
	var smb1 *bool
	if b, err := os.ReadFile("/etc/samba/smb.conf"); err == nil {
		s := strings.ToLower(string(b))
		if strings.Contains(s, "min protocol") {
			v := strings.Contains(s, "nt1") || strings.Contains(s, "lanman")
			smb1 = &v
		}
	}

	data := hygieneFacts(listening, poisoning, smb1, nil)
	if len(data) == 0 {
		return nil, run.SkipError{ReasonText: "no hygiene facts could be read on this system"}
	}
	return data, nil
}

// linuxListeningPorts reads /proc/net/tcp{,6} — state 0A is LISTEN.
func linuxListeningPorts() []int {
	seen := map[int]bool{}
	var out []int
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		udp := strings.Contains(f, "udp")
		lines := strings.Split(strings.TrimSpace(string(b)), "\n")
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			// TCP listeners are state 0A; UDP sockets are "listening" by nature.
			if !udp && fields[3] != "0A" {
				continue
			}
			if i := strings.LastIndex(fields[1], ":"); i > 0 {
				if p, err := strconv.ParseInt(fields[1][i+1:], 16, 32); err == nil && !seen[int(p)] {
					seen[int(p)] = true
					out = append(out, int(p))
				}
			}
		}
	}
	return out
}
