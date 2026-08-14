//go:build linux

package collectors

import (
	"context"
	"os"
	"strings"

	"netdiag/internal/schema"
)

// ------------------------------------------------------- neighbours (L2, §4.1)

// neighCollector reads /proc/net/arp (network-namespace-aware): entry count,
// incomplete-entry ratio, and — the ARP-spoof / dead-gateway signal — the
// gateway's MAC and its cache state. Passive: nothing is transmitted.
type neighCollector struct{}

func (neighCollector) Name() string      { return "neigh" }
func (neighCollector) Privilege() string { return schema.PrivUnprivileged }

func (neighCollector) Collect(_ context.Context) (map[string]any, error) {
	b, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	gwB, _ := os.ReadFile("/proc/net/route")
	gw := defaultGatewayFrom(string(gwB))

	total, incomplete := 0, 0
	gwState, gwMAC := "absent", ""
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 6 {
			continue
		}
		ip, flags, mac := f[0], f[2], f[3]
		total++
		isIncomplete := flags == "0x0" || mac == "00:00:00:00:00:00"
		if isIncomplete {
			incomplete++
		}
		if gw != "" && ip == gw {
			gwMAC = mac
			if isIncomplete {
				gwState = "incomplete"
			} else {
				gwState = "resolved"
			}
		}
	}
	data := map[string]any{
		"neigh_entry_count": total,
		"gateway_arp_state": gwState,
	}
	if total > 0 {
		data["neigh_incomplete_pct"] = incomplete * 100 / total
	}
	if gwMAC != "" && gwState == "resolved" {
		data["gateway_mac"] = gwMAC
	}
	return data, nil
}
