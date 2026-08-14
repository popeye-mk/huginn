//go:build linux

package collectors

import (
	"context"
	"netdiag/internal/schema"
	"os"
	"strconv"
	"strings"
)

// ------------------------------------------------- own sockets (L4, §4.1)

// socketsCollector parses /proc/net/tcp{,6} and udp{,6} — what is listening,
// bound where, and connection-state distribution. Answers "is the service
// actually up and bound?" without exec'ing ss.
type socketsCollector struct{}

func (socketsCollector) Name() string      { return "sockets" }
func (socketsCollector) Privilege() string { return schema.PrivUnprivileged }

func (socketsCollector) Collect(_ context.Context) (map[string]any, error) {
	listen, estab, timeWait := 0, 0, 0
	var listeners []string
	seen := map[string]bool{}
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n")[1:] {
			cols := strings.Fields(line)
			if len(cols) < 4 {
				continue
			}
			switch cols[3] { // st column
			case "0A":
				listen++
				if p := hexPort(cols[1]); p > 0 {
					loop := strings.HasPrefix(cols[1], "0100007F") || // 127.0.0.1
						strings.HasPrefix(cols[1], "00000000000000000000000001000000") // ::1
					key := strconv.Itoa(p)
					if loop {
						key += "(loopback-only)"
					}
					if !seen[key] && len(listeners) < 40 {
						seen[key] = true
						listeners = append(listeners, key)
					}
				}
			case "01":
				estab++
			case "06":
				timeWait++
			}
		}
	}
	udp := 0
	for _, f := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		if b, err := os.ReadFile(f); err == nil {
			udp += len(strings.Split(strings.TrimSpace(string(b)), "\n")) - 1
		}
	}
	return map[string]any{
		"sockets_listening":   listen,
		"sockets_established": estab,
		"sockets_time_wait":   timeWait,
		"sockets_udp":         udp,
		"listening_ports":     listeners,
	}, nil
}

func hexPort(hexAddr string) int { return HexPort(hexAddr) }
