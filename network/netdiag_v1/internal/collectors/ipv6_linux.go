//go:build linux

package collectors

import (
	"context"
	"net"
	"os"
	"strings"
	"time"

	"netdiag/internal/schema"
)

// ------------------------------------------------------ IPv6 health (L3, §4.1)

// ipv6Collector detects the "IPv6 present but broken" state: AAAA resolves,
// the machine has a global v6 address, but the v6 path is dead — producing
// connect-timeout-then-fallback delays that feel exactly like slow internet.
type ipv6Collector struct{}

func (ipv6Collector) Name() string      { return "ipv6" }
func (ipv6Collector) Privilege() string { return schema.PrivUnprivileged }

func (ipv6Collector) Collect(ctx context.Context) (map[string]any, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	global := false
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok &&
				ipnet.IP.To4() == nil && ipnet.IP.IsGlobalUnicast() {
				global = true
			}
		}
	}
	data := map[string]any{
		"ipv6_global_present":        global,
		"ipv6_default_route_present": ipv6DefaultRoute(),
	}
	if !global {
		return data, nil // nothing to probe; the facts above still matter
	}
	// One TCP connect to a public v6 DNS anchor: alive-or-dead, no payload.
	target := "[2606:4700:4700::1111]:53"
	data["ipv6_probe_target"] = target
	d := net.Dialer{Timeout: 2500 * time.Millisecond}
	conn, err := d.DialContext(ctx, "tcp6", target)
	if err == nil {
		conn.Close()
	}
	data["ipv6_path_ok"] = err == nil
	return data, nil
}

// ipv6DefaultRoute: a ::/0 entry in /proc/net/ipv6_route (dest prefix len 00).
func ipv6DefaultRoute() bool {
	b, err := os.ReadFile("/proc/net/ipv6_route")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		f := strings.Fields(line)
		// dest, destPrefix, src, srcPrefix, nexthop, metric, ..., iface
		if len(f) >= 10 && f[0] == strings.Repeat("0", 32) && f[1] == "00" && f[len(f)-1] != "lo" {
			return true
		}
	}
	return false
}
