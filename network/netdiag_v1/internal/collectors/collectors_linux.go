//go:build linux

package collectors

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"netdiag/internal/run"
	"netdiag/internal/schema"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func platformCollectors() []run.Collector {
	return []run.Collector{
		// v0 five
		linkCollector{},
		addressingCollector{},
		routingCollector{},
		dnsCollector{},
		gatewayPingCollector{},
		// v1 passive set (§4.1)
		neighCollector{},
		socketsCollector{},
		qualityCollector{},
		tcpStatsCollector{},
		ntpCollector{},
		dnsExtraCollector{},
		ipv6Collector{},
		captiveCollector{},
		proxyCollector{},
		vpnCollector{},
		wifiCollector{},
		powerCollector{},
		eventsCollector{},
		adCollector{},
		firewallCollector{},
		hygieneCollector{},
	}
}

// ---------------------------------------------------------------- link (L1)

// linkCollector reads /sys/class/net — up/down, speed, duplex, MTU, MAC —
// with no probes and no privilege. Duplex/speed is the NetAlly trick (§4.1).
type linkCollector struct{}

func (linkCollector) Name() string      { return "link" }
func (linkCollector) Privilege() string { return schema.PrivUnprivileged }

func (linkCollector) Collect(_ context.Context) (map[string]any, error) {
	// net.Interfaces() is network-namespace-aware; /sys/class/net is NOT
	// (it shows the mount-time namespace). So the interface list and
	// up/down state come from the stdlib, and /sys only enriches with
	// duplex/speed for interfaces that really exist here.
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	type nic struct {
		Name, OperState, Duplex, MAC string
		SpeedMbps, MTU               int
		Wireless                     bool
	}
	var nics []nic
	primary := nic{SpeedMbps: -1}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		base := filepath.Join("/sys/class/net", ifc.Name)
		state := "down"
		if ifc.Flags&net.FlagUp != 0 && ifc.Flags&net.FlagRunning != 0 {
			state = "up"
		}
		n := nic{
			Name:      ifc.Name,
			OperState: state,
			Duplex:    sysRead(base, "duplex"),
			MAC:       ifc.HardwareAddr.String(),
			SpeedMbps: sysReadInt(base, "speed"),
			MTU:       ifc.MTU,
			// A /sys/class/net/<if>/wireless directory is the kernel's own
			// answer, and does not depend on the name being "wlan0".
			Wireless: dirExists(filepath.Join(base, "wireless")),
		}
		nics = append(nics, n)
		if state == "up" && primary.Name == "" {
			primary = n
		}
	}
	data := map[string]any{
		"link_interface_count": len(nics),
		"link_interfaces":      nics,
	}
	if primary.Name != "" {
		base := filepath.Join("/sys/class/net", primary.Name)
		data["link_primary_interface"] = primary.Name
		data["link_up"] = true
		data["link_mtu"] = primary.MTU
		// Which medium the primary link uses. Rules that judge a NEGOTIATED
		// SPEED need this: 65 Mbps is a bad cable on copper and an ordinary
		// afternoon on Wi-Fi, and without the distinction the tool would tell
		// laptop users to replace a cable they do not have.
		data["link_primary_is_wireless"] = primary.Wireless
		// The kernel's own /sys answer is authoritative here — there is no
		// struct offset to get wrong, so no second source is needed. The fact
		// exists on both platforms so the rules do not need an OS branch.
		data["link_medium_confirmed"] = true
		if primary.Duplex != "" {
			data["link_duplex"] = primary.Duplex
		}
		if primary.SpeedMbps > 0 {
			data["link_speed_mbps"] = primary.SpeedMbps
		}
		// v1: error/drop counters and carrier flaps since boot (§4.1).
		stats := filepath.Join(base, "statistics")
		rxPkts, rxErr := sysReadInt(stats, "rx_packets"), sysReadInt(stats, "rx_errors")
		txPkts, txErr := sysReadInt(stats, "tx_packets"), sysReadInt(stats, "tx_errors")
		if rxPkts >= 0 && rxErr >= 0 {
			data["link_rx_errors"] = rxErr
			data["link_tx_errors"] = txErr
			if total := rxPkts + txPkts; total > 0 {
				data["link_error_rate_pct"] = float64((rxErr+txErr)*10000/total) / 100
			}
		}
		if cc := sysReadInt(base, "carrier_changes"); cc >= 0 {
			data["link_carrier_changes"] = cc
		}
	} else {
		data["link_up"] = false
	}
	// NAC/802.1X reality (partial): is a supplicant managing interfaces?
	// Full auth-state needs the supplicant's control protocol — this is the
	// honest presence check.
	if entries, err := os.ReadDir("/var/run/wpa_supplicant"); err == nil {
		var supIfaces []string
		for _, e := range entries {
			supIfaces = append(supIfaces, e.Name())
		}
		data["dot1x_supplicant_present"] = len(supIfaces) > 0
		if len(supIfaces) > 0 {
			data["dot1x_ifaces"] = supIfaces
			// EAP/PAE state via the control socket (wpactrl_linux.go) —
			// the full 802.1X story, wired included.
			dot1xFromSupplicant(supIfaces, data)
		}
	} else {
		data["dot1x_supplicant_present"] = false
	}
	return data, nil
}

func sysRead(base, f string) string {
	b, err := os.ReadFile(filepath.Join(base, f))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func sysReadInt(base, f string) int {
	v, err := strconv.Atoi(sysRead(base, f))
	if err != nil {
		return -1
	}
	return v
}

// ---------------------------------------------------------- addressing (L3)

// addressingCollector uses the stdlib for IPv4/IPv6 addresses and detects
// the APIPA/link-local-only state ("no DHCP answered", §4.1).
type addressingCollector struct{}

func (addressingCollector) Name() string      { return "addressing" }
func (addressingCollector) Privilege() string { return schema.PrivUnprivileged }

func (addressingCollector) Collect(_ context.Context) (map[string]any, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var v4Global, v4APIPA, v6Global []string
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP
			switch {
			case ip.To4() != nil && ip.IsLinkLocalUnicast():
				v4APIPA = append(v4APIPA, ip.String())
			case ip.To4() != nil && !ip.IsLoopback():
				v4Global = append(v4Global, ip.String())
			case ip.To4() == nil && ip.IsGlobalUnicast():
				v6Global = append(v6Global, ip.String())
			}
		}
	}
	data := map[string]any{
		"ipv4_addresses":  v4Global,
		"ipv6_addresses":  v6Global,
		"has_ipv4_global": len(v4Global) > 0,
		// APIPA-only: 169.254.x.x present and no real IPv4 anywhere → DHCP
		// asked, nobody answered. The single clearest "why no internet".
		"apipa_only": len(v4APIPA) > 0 && len(v4Global) == 0,
	}
	// v1: DHCP lease evidence — best-effort read of the lease files the
	// common clients leave behind; honest absence otherwise (§4.1).
	if server, found := dhcpLeaseServer(); found {
		data["dhcp_lease_found"] = true
		data["dhcp_server"] = server
	} else {
		data["dhcp_lease_found"] = false
	}
	if hoursLeft, ok := dhcpLeaseExpiry(); ok {
		data["dhcp_lease_hours_left"] = float64(int(hoursLeft*10)) / 10
	}
	return data, nil
}

// dhcpLeaseServer scans systemd-networkd, dhclient and NetworkManager lease
// locations for a DHCP server identifier.
func dhcpLeaseServer() (string, bool) {
	patterns := []string{
		"/run/systemd/netif/leases/*",
		"/var/lib/dhcp/dhclient*.leases",
		"/var/lib/NetworkManager/*.lease",
	}
	for _, p := range patterns {
		matches, _ := filepath.Glob(p)
		for _, m := range matches {
			b, err := os.ReadFile(m)
			if err != nil {
				continue
			}
			if v, ok := LeaseServerFrom(string(b)); ok {
				return v, true
			}
		}
	}
	return "", false
}

// dhcpLeaseExpiry parses dhclient's `expire` timestamps ("expire 3
// 2026/07/22 12:00:00;") — hours remaining on the newest lease. Renewal
// state detail for other clients stays on the honest-partial list.
func dhcpLeaseExpiry() (float64, bool) {
	matches, _ := filepath.Glob("/var/lib/dhcp/dhclient*.leases")
	var latest time.Time
	for _, m := range matches {
		b, err := os.ReadFile(m)
		if err != nil {
			continue
		}
		if t, ok := LeaseExpiryFrom(string(b)); ok && t.After(latest) {
			latest = t
		}
	}
	if latest.IsZero() {
		return 0, false
	}
	return time.Until(latest).Hours(), true
}

// ------------------------------------------------------------- routing (L3)

// routingCollector parses /proc/net/route for the default gateway —
// no exec of `ip`, no netlink dependency, works on any Linux since 2.2.
type routingCollector struct{}

func (routingCollector) Name() string      { return "routing" }
func (routingCollector) Privilege() string { return schema.PrivUnprivileged }

func (routingCollector) Collect(_ context.Context) (map[string]any, error) {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	var gw, gwIface string
	type defRoute struct {
		iface  string
		metric int
	}
	var defaults []defRoute
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) < 7 || f[1] != "00000000" { // destination 0.0.0.0/0
			continue
		}
		raw, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil {
			continue
		}
		metric, _ := strconv.Atoi(f[6])
		defaults = append(defaults, defRoute{f[0], metric})
		if gw == "" {
			ip := make(net.IP, 4)
			binary.LittleEndian.PutUint32(ip, uint32(raw)) // /proc stores little-endian hex
			gw, gwIface = ip.String(), f[0]
		}
	}
	// v1: metric conflicts — two default routes on different interfaces
	// (Wi-Fi + Ethernet both default, wrong one possibly winning, §4.1).
	conflictIfaces := map[string]bool{}
	for _, d := range defaults {
		conflictIfaces[d.iface] = true
	}
	return map[string]any{
		"default_route_present":  gw != "" && gw != "0.0.0.0",
		"gateway_ip":             gw,
		"gateway_interface":      gwIface,
		"default_route_count":    len(defaults),
		"default_route_conflict": len(conflictIfaces) > 1,
		"route_table_size":       len(lines) - 1,
	}, nil
}

// ----------------------------------------------------------------- dns (L7)

// dnsCollector reads /etc/resolv.conf and performs one resolution test
// against a known-good name, timing the answer.
type dnsCollector struct{}

func (dnsCollector) Name() string      { return "dns" }
func (dnsCollector) Privilege() string { return schema.PrivUnprivileged }

func (dnsCollector) Collect(ctx context.Context) (map[string]any, error) {
	var servers []string
	if b, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && f[0] == "nameserver" {
				servers = append(servers, f[1])
			}
		}
	}
	data := map[string]any{
		"dns_servers":       servers,
		"dns_servers_count": len(servers),
	}
	start := time.Now()
	addrs, err := net.DefaultResolver.LookupHost(ctx, dnsProbeName)
	data["dns_resolution_ok"] = err == nil && len(addrs) > 0
	if err == nil {
		data["dns_latency_ms"] = time.Since(start).Milliseconds()
	} else {
		data["dns_error"] = err.Error()
	}
	return data, nil
}

// -------------------------------------------------- gateway reachability (L3)

// gatewayPingCollector sends ICMP echoes to the default gateway using an
// unprivileged ICMP datagram socket first, then a raw socket if elevated.
// If neither is permitted it reports an honest skip — never a fake green.
type gatewayPingCollector struct{}

func (gatewayPingCollector) Name() string      { return "gateway_ping" }
func (gatewayPingCollector) Privilege() string { return schema.PrivUnprivileged }

func (gatewayPingCollector) Collect(ctx context.Context) (map[string]any, error) {
	gwB, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil, err
	}
	gw := defaultGatewayFrom(string(gwB))
	if gw == "" {
		return nil, run.SkipError{ReasonText: "no default gateway to probe"}
	}
	const count = 3
	sent, received := 0, 0
	var totalRTT time.Duration
	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			break
		}
		rtt, err := icmpEcho(gw, i, 800*time.Millisecond)
		sent++
		if err == nil {
			received++
			totalRTT += rtt
		} else if isPermissionErr(err) {
			return nil, run.SkipError{ReasonText: "ICMP not permitted at this privilege (see --explain-privileges)"}
		}
	}
	data := map[string]any{
		"gateway_probe_target": gw,
		"gateway_probe_sent":   sent,
		"gateway_reachable":    received > 0,
		"gateway_loss_pct":     int(float64(sent-received) / float64(max(sent, 1)) * 100),
		"probe_method":         "icmp_echo",
	}
	if received > 0 {
		data["gateway_rtt_avg_ms"] = float64(totalRTT.Microseconds()) / float64(received) / 1000.0
	}
	return data, nil
}

// defaultGatewayFrom delegates to the tested parser in parse.go — the
// little-endian hex layout of /proc/net/route is exactly the sort of detail
// that deserves a fixture rather than a second implementation.
func defaultGatewayFrom(routeTable string) string {
	return DefaultGatewayFromRoute(routeTable)
}

func isPermissionErr(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "operation not permitted") ||
		strings.Contains(err.Error(), "permission denied"))
}

var _ = fmt.Sprintf // keep fmt for future use without lint noise

// dirExists is used to ask the kernel what kind of interface this is, rather
// than guessing from its name.
func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}
