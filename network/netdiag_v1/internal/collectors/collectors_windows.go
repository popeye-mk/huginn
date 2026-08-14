//go:build windows

// The Windows collector set (§17.4): stdlib net.* where it is cross-platform,
// IP Helper (iphlpapi.dll via LazyDLL, win_api_windows.go) for tables and
// ICMP, and the OS's own tools (netsh, wevtutil, dsregcmd, nltest, reg,
// certutil) where Windows puts the truth behind a CLI. Anything that fails
// reports an honest skip or an absent fact — never a fake green.
package collectors

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"netdiag/internal/run"
	"netdiag/internal/schema"
)

func platformCollectors() []run.Collector {
	return []run.Collector{
		winLinkCollector{},
		winAddressingCollector{},
		winRoutingCollector{},
		winDNSCollector{},
		winGatewayPingCollector{},
		winNeighCollector{},
		winSocketsCollector{},
		winQualityCollector{},
		winTCPStatsCollector{},
		winNTPCollector{},
		winDNSExtraCollector{},
		winIPv6Collector{},
		captiveCollector{}, // shared pure-Go probe
		winProxyCollector{},
		winVPNCollector{},
		winWifiCollector{},
		winPowerCollector{},
		winEventsCollector{},
		winADCollector{},
		winFirewallCollector{},
		winSpoolerCollector{},
		winHygieneCollector{},
	}
}

// winSpoolerCollector: the LOCAL half of a print ticket (§6.1). Half of
// "I can't print" is not a network fault at all — the spooler is stopped or
// the queue is jammed with a stuck job — and a network tool that only probes
// port 9100 confidently blames the wrong thing. Judged by exit codes and
// state keywords, never by localized display text (French-Windows lesson).
type winSpoolerCollector struct{}

func (winSpoolerCollector) Name() string      { return "print_spooler" }
func (winSpoolerCollector) Privilege() string { return schema.PrivUnprivileged }

func (winSpoolerCollector) Collect(ctx context.Context) (map[string]any, error) {
	data := map[string]any{}

	// Service state: `sc query spooler` prints STATE : 4 RUNNING — the
	// NUMBER is stable across locales, the word is not.
	out, err := runTool(ctx, "sc", "query", "spooler")
	if err != nil {
		return nil, run.SkipError{ReasonText: "sc query spooler unavailable: " + err.Error()}
	}
	// Parsed by internal/collectors/parse.go — judged by the numeric state,
	// because "STATE" is "ÉTAT" on French Windows and the word-matching
	// version reported every service as stopped there (caught by parse_test).
	running, measured := SCServiceRunning(out)
	if !measured {
		return nil, run.SkipError{ReasonText: "could not read the spooler's service state from sc query"}
	}
	data["spooler_running"] = running
	if !running {
		return data, nil // a stopped spooler is the whole answer
	}

	// Queue depth and stuck jobs, via PowerShell's printing cmdlets. Absent
	// on some SKUs (Core installs) — honest absence, never a silent zero.
	ps := "$j=@(Get-Printer -ErrorAction Stop | Get-PrintJob -ErrorAction SilentlyContinue);" +
		"$e=@($j | Where-Object { $_.JobStatus -match 'Error|Blocked|Offline|PaperOut|Deleting' });" +
		"'JOBS=' + $j.Count + ';ERR=' + $e.Count + ';OLD=' + " +
		"@($j | Where-Object { $_.SubmittedTime -lt (Get-Date).AddMinutes(-15) }).Count"
	if q, err := runTool(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", ps); err == nil {
		counts := PrintQueueCounts(q)
		if n, ok := counts["depth"]; ok {
			data["print_queue_depth"] = n
		}
		if n, ok := counts["errored"]; ok {
			data["print_jobs_errored"] = n
		}
		if n, ok := counts["stale"]; ok {
			data["print_jobs_stuck_15min"] = n
		}
	} else {
		data["print_queue_readable"] = false
	}

	// Default printer target, so cant-print can say WHICH device it probed.
	dp := "(Get-CimInstance Win32_Printer -Filter 'Default=True' | " +
		"Select-Object -First 1 -ExpandProperty PortName)"
	if p, err := runTool(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", dp); err == nil {
		if port := strings.TrimSpace(p); port != "" {
			data["default_printer_port"] = port
		}
	}
	return data, nil
}

// runTool executes one of the OS's own diagnostic tools with a timeout.
func runTool(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	return string(out), err
}

// ---------------------------------------------------------------- link (L1)

type winLinkCollector struct{}

// IANA ifType, as reported by MIB_IFROW.dwType: 6 = ethernet, 71 = 802.11.
const ifTypeIEEE80211 = 71

func (winLinkCollector) Name() string      { return "link" }
func (winLinkCollector) Privilege() string { return schema.PrivUnprivileged }

func (winLinkCollector) Collect(ctx context.Context) (map[string]any, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	ifRows, _ := winIfTable() // speed + error counters, best-effort
	rowByIndex := map[int]winIfRow{}
	for _, r := range ifRows {
		rowByIndex[r.index] = r
	}
	type nic struct {
		Name, OperState, MAC string
		SpeedMbps, MTU       int
		Wireless             bool
	}
	var nics []nic
	primary := nic{}
	primaryIdx := 0
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagLoopback != 0 || isVirtualWinIface(ifc.Name) {
			continue
		}
		state := "down"
		if ifc.Flags&net.FlagUp != 0 && ifc.Flags&net.FlagRunning != 0 {
			state = "up"
		}
		n := nic{Name: ifc.Name, OperState: state, MAC: ifc.HardwareAddr.String(), MTU: ifc.MTU}
		if r, ok := rowByIndex[ifc.Index]; ok {
			if r.speedMbps > 0 && r.speedMbps < 100000 {
				n.SpeedMbps = r.speedMbps
			}
			n.Wireless = r.ifType == ifTypeIEEE80211
		}
		nics = append(nics, n)
		if state == "up" && primary.Name == "" {
			primary, primaryIdx = n, ifc.Index
		}
	}
	data := map[string]any{
		"link_interface_count": len(nics),
		"link_interfaces":      nics,
	}
	if primary.Name != "" {
		data["link_primary_interface"] = primary.Name
		data["link_up"] = true
		data["link_mtu"] = primary.MTU
		// See the Linux collector: a low negotiated speed means a cable fault on
		// copper and nothing at all on Wi-Fi. On Windows the medium comes from
		// a struct offset, so it is CONFIRMED against netsh before any rule is
		// allowed to act on it. Disagreement means the tool says nothing.
		data["link_primary_is_wireless"] = primary.Wireless
		data["link_medium_confirmed"] = confirmWinMedium(ctx, primary.Name, primary.Wireless)
		if primary.SpeedMbps > 0 {
			data["link_speed_mbps"] = primary.SpeedMbps
		}
		// Duplex is not exposed by IP Helper — honestly absent on Windows.
		if r, ok := rowByIndex[primaryIdx]; ok {
			data["link_rx_errors"] = r.inErrors
			data["link_tx_errors"] = r.outErrors
			if total := r.inPackets + r.outPackets; total > 0 {
				data["link_error_rate_pct"] = float64((r.inErrors+r.outErrors)*10000/total) / 100
			}
		}
	} else {
		data["link_up"] = false
	}
	return data, nil
}

// isVirtualWinIface filters the adapters that would make a healthy laptop
// look multi-homed (WSL, Hyper-V, loopback pseudo-interfaces).
func isVirtualWinIface(name string) bool {
	l := strings.ToLower(name)
	for _, p := range []string{"loopback", "vethernet", "wsl", "virtualbox host-only", "vmware network adapter", "teredo", "isatap"} {
		if strings.Contains(l, p) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------- addressing (L3)

type winAddressingCollector struct{}

func (winAddressingCollector) Name() string      { return "addressing" }
func (winAddressingCollector) Privilege() string { return schema.PrivUnprivileged }

func (winAddressingCollector) Collect(ctx context.Context) (map[string]any, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var v4Global, v4APIPA, v6Global []string
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 || isVirtualWinIface(ifc.Name) {
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
		"apipa_only":      len(v4APIPA) > 0 && len(v4Global) == 0,
	}
	// DHCP facts come from the registry first. The IP_ADAPTER_INFO struct
	// walk below it is hand-offset arithmetic over a struct with
	// platform-dependent padding, and a Win 11 field run proved it wrong
	// (reported "255" where the real server was 10.0.0.10). The registry
	// values are documented, stable, and NOT localized — the same reason
	// nltest is judged by exit code rather than by its French output.
	if server, hoursLeft, ok := winDHCPFromRegistry(ctx, v4Global); ok {
		data["dhcp_lease_found"] = true
		data["dhcp_server"] = server
		if hoursLeft != 0 {
			data["dhcp_lease_hours_left"] = float64(int(hoursLeft*10)) / 10
		}
	} else if server, hoursLeft, ok := winDHCPInfo(); ok && plausibleIPv4(server) {
		data["dhcp_lease_found"] = true
		data["dhcp_server"] = server
		data["dhcp_source"] = "ip-helper"
		if hoursLeft != 0 {
			data["dhcp_lease_hours_left"] = float64(int(hoursLeft*10)) / 10
		}
	} else {
		data["dhcp_lease_found"] = false
	}
	return data, nil
}

// plausibleIPv4 now lives in parse.go: it is pure, and the "255" bug it was
// written for deserves a test that runs on every platform, not just Windows.

// winDHCPFromRegistry reads the DHCP lease facts Windows records per
// interface under Tcpip\Parameters\Interfaces\{GUID}. Value NAMES and data
// are locale-independent. When several interfaces have leases, the one whose
// DhcpIPAddress matches an address actually configured on this machine wins.
func winDHCPFromRegistry(ctx context.Context, ownIPs []string) (server string, hoursLeft float64, ok bool) {
	out, err := runTool(ctx, "reg", "query",
		`HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`, "/s")
	if err != nil {
		return "", 0, false
	}
	mine := map[string]bool{}
	for _, ip := range ownIPs {
		mine[ip] = true
	}
	// Prefer the interface whose leased address this machine actually holds;
	// fall back to any block with a plausible server (parse_test pins both).
	var fallback DHCPLease
	for _, l := range DHCPFromRegistry(out) {
		if !plausibleIPv4(l.Server) {
			continue
		}
		if mine[l.IPAddress] {
			return l.Server, hoursUntil(l.ExpiryUTC), true
		}
		if fallback.Server == "" {
			fallback = l
		}
	}
	if fallback.Server != "" {
		return fallback.Server, hoursUntil(fallback.ExpiryUTC), true
	}
	return "", 0, false
}

func hoursUntil(unixSeconds int64) float64 {
	if unixSeconds <= 0 {
		return 0
	}
	return time.Until(time.Unix(unixSeconds, 0)).Hours()
}

// ------------------------------------------------------------- routing (L3)

type winRoutingCollector struct{}

func (winRoutingCollector) Name() string      { return "routing" }
func (winRoutingCollector) Privilege() string { return schema.PrivUnprivileged }

func (winRoutingCollector) Collect(_ context.Context) (map[string]any, error) {
	rows, err := winRouteTable()
	if err != nil {
		return nil, err
	}
	var gw string
	gwIface := ""
	defaults := map[int]bool{}
	count := 0
	for _, r := range rows {
		if r.dest != "0.0.0.0" || r.mask != "0.0.0.0" {
			continue
		}
		count++
		defaults[r.ifIndex] = true
		if gw == "" {
			gw = r.nextHop
			if ifc, err := net.InterfaceByIndex(r.ifIndex); err == nil {
				gwIface = ifc.Name
			}
		}
	}
	return map[string]any{
		"default_route_present":  gw != "" && gw != "0.0.0.0",
		"gateway_ip":             gw,
		"gateway_interface":      gwIface,
		"default_route_count":    count,
		"default_route_conflict": len(defaults) > 1,
		"route_table_size":       len(rows),
	}, nil
}

func winDefaultGateway() string {
	rows, err := winRouteTable()
	if err != nil {
		return ""
	}
	for _, r := range rows {
		if r.dest == "0.0.0.0" && r.mask == "0.0.0.0" && r.nextHop != "0.0.0.0" {
			return r.nextHop
		}
	}
	return ""
}

// ----------------------------------------------------------------- dns (L7)

type winDNSCollector struct{}

func (winDNSCollector) Name() string      { return "dns" }
func (winDNSCollector) Privilege() string { return schema.PrivUnprivileged }

func (winDNSCollector) Collect(ctx context.Context) (map[string]any, error) {
	servers := winDNSServers()
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

type winGatewayPingCollector struct{}

func (winGatewayPingCollector) Name() string      { return "gateway_ping" }
func (winGatewayPingCollector) Privilege() string { return schema.PrivUnprivileged }

func (winGatewayPingCollector) Collect(ctx context.Context) (map[string]any, error) {
	gw := winDefaultGateway()
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
		rtt, err := icmpEchoWin(gw, 800*time.Millisecond)
		sent++
		if err == nil {
			received++
			totalRTT += rtt
		}
	}
	data := map[string]any{
		"gateway_probe_target": gw,
		"gateway_probe_sent":   sent,
		"gateway_reachable":    received > 0,
		"gateway_loss_pct":     (sent - received) * 100 / max(sent, 1),
		"probe_method":         "IcmpSendEcho",
	}
	if received > 0 {
		data["gateway_rtt_avg_ms"] = float64(totalRTT.Microseconds()) / float64(received) / 1000.0
	}
	return data, nil
}

// ---------------------------------------------------------------- neigh (L2)

type winNeighCollector struct{}

func (winNeighCollector) Name() string      { return "neigh" }
func (winNeighCollector) Privilege() string { return schema.PrivUnprivileged }

func (winNeighCollector) Collect(_ context.Context) (map[string]any, error) {
	rows, err := winArpTable()
	if err != nil {
		return nil, err
	}
	gw := winDefaultGateway()
	total, incomplete := 0, 0
	gwState, gwMAC := "absent", ""
	for _, r := range rows {
		total++
		bad := r.typ == 2 || r.mac == "" // invalid / unresolved
		if bad {
			incomplete++
		}
		if gw != "" && r.ip == gw {
			if bad {
				gwState = "incomplete"
			} else {
				gwState, gwMAC = "resolved", r.mac
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
	if gwMAC != "" {
		data["gateway_mac"] = gwMAC
	}
	return data, nil
}

// -------------------------------------------------------------- sockets (L4)

type winSocketsCollector struct{}

func (winSocketsCollector) Name() string      { return "sockets" }
func (winSocketsCollector) Privilege() string { return schema.PrivUnprivileged }

func (winSocketsCollector) Collect(_ context.Context) (map[string]any, error) {
	conns, err := winTCPTable()
	if err != nil {
		return nil, err
	}
	listen, estab, timeWait := 0, 0, 0
	var listeners []string
	seen := map[string]bool{}
	for _, c := range conns {
		switch c.state {
		case 2:
			listen++
			key := strconv.Itoa(c.localPort)
			if c.localLoopback {
				key += "(loopback-only)"
			}
			if !seen[key] && len(listeners) < 40 {
				seen[key] = true
				listeners = append(listeners, key)
			}
		case 5:
			estab++
		case 11:
			timeWait++
		}
	}
	data := map[string]any{
		"sockets_listening":   listen,
		"sockets_established": estab,
		"sockets_time_wait":   timeWait,
		"listening_ports":     listeners,
	}
	if u := winUDPCount(); u >= 0 {
		data["sockets_udp"] = u
	}
	return data, nil
}

// ---------------------------------------------------------- net_quality (L3)

type winQualityCollector struct{}

func (winQualityCollector) Name() string           { return "net_quality" }
func (winQualityCollector) Privilege() string      { return schema.PrivUnprivileged }
func (winQualityCollector) Timeout() time.Duration { return 15 * time.Second }

func (winQualityCollector) Collect(ctx context.Context) (map[string]any, error) {
	gw := winDefaultGateway()
	if gw == "" {
		return nil, run.SkipError{ReasonText: "no default route — no path to measure"}
	}
	data := map[string]any{"upstream_probe_target": upstreamAddr}
	gwStats := winProbeWindow(ctx, gw)
	gwStats.fill(data, "gateway_q")
	upStats := winProbeWindow(ctx, upstreamAddr)
	upStats.fill(data, "upstream")
	data["upstream_reachable"] = upStats.received > 0
	// Path-MTU read needs IP_MTU-equivalent (GetIpPathTable) — v-next.
	return data, nil
}

func winProbeWindow(ctx context.Context, target string) windowStats {
	var w windowStats
	for i := 0; i < qualityProbes; i++ {
		if ctx.Err() != nil {
			break
		}
		rtt, err := icmpEchoWin(target, 700*time.Millisecond)
		w.sent++
		if err == nil {
			w.received++
			w.rtts = append(w.rtts, float64(rtt.Microseconds())/1000.0)
		}
	}
	return w
}

// ------------------------------------------------------------ tcp_stats (L4)

type winTCPStatsCollector struct{}

func (winTCPStatsCollector) Name() string      { return "tcp_stats" }
func (winTCPStatsCollector) Privilege() string { return schema.PrivUnprivileged }

func (winTCPStatsCollector) Collect(_ context.Context) (map[string]any, error) {
	st, err := winTCPStatistics()
	if err != nil {
		return nil, err
	}
	data := map[string]any{
		"tcp_out_segs":      st.outSegs,
		"tcp_retrans_segs":  st.retransSegs,
		"tcp_resets_out":    st.outRsts,
		"tcp_attempt_fails": st.attemptFails,
		"tcp_estab_resets":  st.estabResets,
	}
	// Ratios only above a minimum volume — on a near-idle machine a tiny
	// denominator turns noise into a "storm" (field-run lesson: 473/1k
	// resets on a freshly booted DC).
	if st.outSegs >= 1000 {
		data["tcp_retrans_pct"] = float64(st.retransSegs*1000/st.outSegs) / 10
		data["tcp_resets_per_1k"] = st.outRsts * 1000 / st.outSegs
	}
	return data, nil
}

// ------------------------------------------------------------ time_sync (L7)

type winNTPCollector struct{}

func (winNTPCollector) Name() string      { return "time_sync" }
func (winNTPCollector) Privilege() string { return schema.PrivUnprivileged }

func (winNTPCollector) Collect(ctx context.Context) (map[string]any, error) {
	data := map[string]any{}
	server := ""
	if out, err := runTool(ctx, "w32tm", "/query", "/source"); err == nil {
		src := strings.TrimSpace(out)
		data["time_sync_configured"] = src != "" && !strings.Contains(strings.ToLower(src), "free-running")
		data["time_sync_daemon"] = "w32time (" + src + ")"
		if !strings.Contains(src, " ") && strings.Contains(src, ".") {
			server = strings.TrimSuffix(src, ",0x9")
		}
	} else {
		data["time_sync_configured"] = false
	}
	if server == "" {
		server = "pool.ntp.org"
	}
	offset, used, err := sntpOffset(ctx, server)
	data["ntp_query_ok"] = err == nil
	if err == nil {
		data["ntp_server_used"] = used
		data["ntp_offset_ms"] = offset.Abs().Milliseconds()
	} else {
		data["ntp_error"] = err.Error()
	}
	return data, nil
}

// ------------------------------------------------------------ dns_extra (L7)

type winDNSExtraCollector struct{}

func (winDNSExtraCollector) Name() string           { return "dns_extra" }
func (winDNSExtraCollector) Privilege() string      { return schema.PrivUnprivileged }
func (winDNSExtraCollector) Timeout() time.Duration { return 10 * time.Second }

func (winDNSExtraCollector) Collect(ctx context.Context) (map[string]any, error) {
	data := map[string]any{}

	overrides := hostsOverrides(`C:\Windows\System32\drivers\etc\hosts`)
	data["hosts_override_count"] = len(overrides)
	if len(overrides) > 0 {
		data["hosts_overrides"] = overrides
	}

	data["browser_doh"] = firefoxDoHFromGlobs(
		firstEnv("APPDATA") + `\Mozilla\Firefox\Profiles\*\prefs.js`,
	)
	data["chrome_doh_policy"] = winChromeDoHPolicy(ctx)

	doh, dot := winDoHConnections()
	data["doh_connections_active"] = len(doh) > 0
	data["dot_connections_active"] = len(dot) > 0
	if len(doh) > 0 {
		data["doh_connection_targets"] = doh
	}
	if len(dot) > 0 {
		data["dot_connection_targets"] = dot
	}

	servers := winDNSServers()
	answers := map[string][]string{}
	var hijack bool
	for _, s := range servers {
		ips, err := queryVia(ctx, s, dnsProbeName)
		if err != nil {
			answers[s] = []string{"error: " + err.Error()}
			continue
		}
		for _, ip := range ips {
			if p := net.ParseIP(ip); p != nil && p.IsPrivate() {
				hijack = true
			}
		}
		answers[s] = ips
	}
	data["dns_public_name_private_ip"] = hijack
	if len(answers) > 0 {
		data["resolver_answers"] = answers
	}
	if len(servers) > 1 {
		data["resolvers_disagree"] = disagree(answers)
	}
	if len(servers) > 0 {
		data["dnssec_probe_name"] = dnssecProbeName
		if validating, err := dnssecValidating(ctx, servers[0], dnssecProbeName); err == nil {
			data["dnssec_validating"] = validating
		}
	}
	return data, nil
}

func winChromeDoHPolicy(ctx context.Context) string {
	out, err := runTool(ctx, "reg", "query", `HKLM\SOFTWARE\Policies\Google\Chrome`, "/v", "DnsOverHttpsMode")
	if err != nil {
		return "unset"
	}
	l := strings.ToLower(out)
	if strings.Contains(l, "secure") || strings.Contains(l, "automatic") {
		return "enabled"
	}
	if strings.Contains(l, "off") {
		return "disabled"
	}
	return "unset"
}

func winDoHConnections() (doh []string, dot []string) {
	conns, err := winTCPTable()
	if err != nil {
		return nil, nil
	}
	for _, c := range conns {
		if c.state != 5 || !dohProviderIPs[c.remoteAddr] {
			continue
		}
		switch c.remotePort {
		case 443:
			doh = appendUnique(doh, c.remoteAddr)
		case 853:
			dot = appendUnique(dot, c.remoteAddr)
		}
	}
	return doh, dot
}

// ----------------------------------------------------------------- ipv6 (L3)

type winIPv6Collector struct{}

func (winIPv6Collector) Name() string      { return "ipv6" }
func (winIPv6Collector) Privilege() string { return schema.PrivUnprivileged }

func (winIPv6Collector) Collect(ctx context.Context) (map[string]any, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	global := false
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 || isVirtualWinIface(ifc.Name) {
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
	data := map[string]any{"ipv6_global_present": global}
	// v6 route table needs GetIpForwardTable2 — route fact honestly absent.
	if !global {
		return data, nil
	}
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

// ---------------------------------------------------------------- proxy (L7)

type winProxyCollector struct{}

func (winProxyCollector) Name() string      { return "proxy" }
func (winProxyCollector) Privilege() string { return schema.PrivUnprivileged }

func (winProxyCollector) Collect(ctx context.Context) (map[string]any, error) {
	data := map[string]any{}
	out, _ := runTool(ctx, "reg", "query",
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`)
	proxyEnabled := strings.Contains(out, "ProxyEnable") && strings.Contains(out, "0x1")
	proxyServer := regValue(out, "ProxyServer")
	pacURL := regValue(out, "AutoConfigURL")
	data["proxy_configured"] = proxyEnabled && proxyServer != ""
	if proxyEnabled && proxyServer != "" {
		data["proxy_url"] = proxyServer
		if host := proxyHostPort(proxyServer); host != "" {
			d := net.Dialer{Timeout: 2 * time.Second}
			conn, err := d.DialContext(ctx, "tcp", host)
			if err == nil {
				conn.Close()
			}
			data["proxy_reachable"] = err == nil
		}
	}
	wctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(wctx, "wpad")
	wpad := err == nil && len(addrs) > 0
	data["wpad_resolvable"] = wpad
	if pacURL == "" && wpad {
		pacURL = "http://wpad/wpad.dat"
	}
	if pacURL != "" {
		data["pac_url_configured"] = true
		fetched, valid := fetchPAC(ctx, pacURL)
		data["pac_fetched"] = fetched
		data["pac_valid"] = valid
	}
	// TLS-inspection CA scan via certutil (root + intermediate stores).
	vendors := []string{"Zscaler", "Fortinet", "FortiGate", "Blue Coat", "Bluecoat",
		"Netskope", "Forcepoint", "WatchGuard", "Sophos", "Cisco Umbrella", "Menlo Security"}
	found := ""
	for _, store := range []string{"Root", "CA"} {
		if out, err := runTool(ctx, "certutil", "-store", store); err == nil {
			for _, v := range vendors {
				if strings.Contains(out, v) {
					found = v
				}
			}
		}
	}
	data["tls_inspection_ca_suspected"] = found != ""
	if found != "" {
		data["tls_inspection_ca_vendor"] = found
	}
	return data, nil
}

func regValue(out, key string) string {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == key {
			return strings.TrimSpace(f[len(f)-1])
		}
	}
	return ""
}

// ------------------------------------------------------------------ vpn (L3)

type winVPNCollector struct{}

func (winVPNCollector) Name() string      { return "vpn" }
func (winVPNCollector) Privilege() string { return schema.PrivUnprivileged }

func (winVPNCollector) Collect(_ context.Context) (map[string]any, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var vpnIfs []string
	active, debris := 0, 0
	vpnIdx := map[int]bool{}
	for _, ifc := range ifs {
		if !isWinVPNIface(ifc.Name) {
			continue
		}
		state := "down"
		if ifc.Flags&net.FlagUp != 0 {
			state = "up"
			active++
		} else {
			debris++ // the leftover-TAP-adapter story (§4.1)
		}
		vpnIdx[ifc.Index] = true
		vpnIfs = append(vpnIfs, ifc.Name+"("+state+")")
	}
	data := map[string]any{
		"vpn_interface_count": len(vpnIfs),
		"vpn_active":          active > 0,
		"vpn_debris_count":    debris,
	}
	if len(vpnIfs) > 0 {
		data["vpn_interfaces"] = vpnIfs
	}
	full := false
	if rows, err := winRouteTable(); err == nil {
		for _, r := range rows {
			if r.dest == "0.0.0.0" && r.mask == "0.0.0.0" && vpnIdx[r.ifIndex] {
				full = true
			}
		}
	}
	data["vpn_default_route"] = full
	return data, nil
}

func isWinVPNIface(name string) bool {
	l := strings.ToLower(name)
	for _, p := range []string{"tap", "tun", "wintun", "wireguard", "vpn", "ppp", "tailscale", "zerotier", "openvpn", "nordlynx"} {
		if strings.Contains(l, p) {
			return true
		}
	}
	return false
}

// confirmWinMedium is the second opinion on MIB_IFROW.dwType. It returns true
// only when netsh agrees with the struct read — either both say this adapter
// is wireless, or netsh lists no wireless adapter with this name and the
// struct also said wired.
//
// If netsh cannot be run, or its locale is one whose adapter-name key we do
// not recognise, the answer is UNCONFIRMED. That is deliberate: an unconfirmed
// medium blocks the rules that depend on it, which costs a finding. A wrong
// medium costs the user a new cable and their trust.
func confirmWinMedium(ctx context.Context, ifaceName string, structSaysWireless bool) bool {
	out, err := runTool(ctx, "netsh", "wlan", "show", "interfaces")
	if err != nil {
		return false
	}
	if strings.Contains(out, "There is no wireless interface") {
		// No WLAN adapters exist at all. That confirms "wired" and refutes
		// "wireless".
		return !structSaysWireless
	}
	netshSaysWireless := false
	for _, n := range WlanInterfaceNames(out) {
		if strings.EqualFold(strings.TrimSpace(n), strings.TrimSpace(ifaceName)) {
			netshSaysWireless = true
			break
		}
	}
	// No names parsed at all → unknown locale → refuse to confirm either way.
	if len(WlanInterfaceNames(out)) == 0 {
		return false
	}
	return netshSaysWireless == structSaysWireless
}

// ----------------------------------------------------------------- wifi (L1)

type winWifiCollector struct{}

func (winWifiCollector) Name() string      { return "wifi" }
func (winWifiCollector) Privilege() string { return schema.PrivUnprivileged }

func (winWifiCollector) Collect(ctx context.Context) (map[string]any, error) {
	out, err := runTool(ctx, "netsh", "wlan", "show", "interfaces")
	if err != nil {
		return nil, run.SkipError{ReasonText: "netsh wlan unavailable (no WLAN service?)"}
	}
	if strings.Contains(out, "There is no wireless interface") {
		return map[string]any{"wifi_present": false}, nil
	}
	get := func(key string) string { return NetshValue(out, key) }
	data := map[string]any{"wifi_present": true}
	if v := get("Name"); v != "" {
		data["wifi_interface"] = v
	}
	if v := get("SSID"); v != "" && !strings.HasPrefix(v, "BSSID") {
		data["wifi_ssid"] = v
	}
	if v := get("BSSID"); v != "" {
		data["wifi_bssid"] = strings.ToLower(v)
	}
	if v := get("Channel"); v != "" {
		if ch, err := strconv.Atoi(v); err == nil {
			data["wifi_channel"] = ch
			if ch > 14 {
				data["wifi_band"] = "5GHz"
			} else {
				data["wifi_band"] = "2.4GHz"
			}
		}
	}
	if v := get("Signal"); strings.HasSuffix(v, "%") {
		if pct, err := strconv.Atoi(strings.TrimSuffix(v, "%")); err == nil {
			data["wifi_link_quality"] = float64(pct)
			// Standard WLAN-API mapping: dBm ≈ quality/2 − 100 (approximate).
			data["wifi_signal_dbm"] = float64(pct)/2 - 100
		}
	}
	if v := get("Receive rate (Mbps)"); v != "" {
		if r, err := strconv.ParseFloat(v, 64); err == nil {
			data["wifi_phy_rate_mbps"] = int(r)
		}
	}
	return data, nil
}

// ------------------------------------------------------------ nic_power (L1)

type winPowerCollector struct{}

func (winPowerCollector) Name() string      { return "nic_power" }
func (winPowerCollector) Privilege() string { return schema.PrivUnprivileged }

func (winPowerCollector) Collect(ctx context.Context) (map[string]any, error) {
	// PnPCapabilities per NIC class key: bit 5 clear = Windows may power
	// the device down ("Allow the computer to turn off this device").
	out, err := runTool(ctx, "reg", "query",
		`HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e11e-11ce-bfc1-08002be10318}`,
		"/s", "/v", "PnPCapabilities")
	if err != nil {
		// reg query exits 1 when no adapter has the value set — common on
		// VMs (virtio NICs expose no power management).
		return nil, run.SkipError{ReasonText: "no NIC exposes PnPCapabilities (typical for VM/virtio adapters)"}
	}
	saving, measured := PnPPowerSaving(out)
	if !measured {
		return nil, run.SkipError{ReasonText: "no NIC exposes PnPCapabilities (typical for VM/virtio adapters)"}
	}
	return map[string]any{
		"nic_power_saving": saving,
	}, nil
}

// -------------------------------------------------------- event_history (L1)

type winEventsCollector struct{}

func (winEventsCollector) Name() string           { return "event_history" }
func (winEventsCollector) Privilege() string      { return schema.PrivUnprivileged }
func (winEventsCollector) Timeout() time.Duration { return 12 * time.Second }

func (winEventsCollector) Collect(ctx context.Context) (map[string]any, error) {
	window := int64(EventWindowHours) * 3600 * 1000
	timeQ := "*[System[TimeCreated[timediff(@SystemTime) <= " + strconv.FormatInt(window, 10) + "]]]"
	data := map[string]any{"events_window_hours": EventWindowHours, "events_source": "wevtutil"}
	okAny := false
	// NetworkProfile DISCONNECTS only (event 10001) — the log also carries
	// chatty state-change events that are not flaps (field-run lesson:
	// counting everything produced 82 "flaps" on a healthy DC).
	if out, err := runTool(ctx, "wevtutil", "qe", "Microsoft-Windows-NetworkProfile/Operational",
		"/q:*[System[(EventID=10001) and TimeCreated[timediff(@SystemTime) <= "+strconv.FormatInt(window, 10)+"]]]",
		"/f:text", "/c:500"); err == nil {
		okAny = true
		// Bug #31 applies here too, and Windows cannot answer it: the NIC
		// link events queried here are not filtered by adapter, so the count
		// may include a disconnected ethernet port. It is reported as
		// UNATTRIBUTED, which stops link_flap_history firing and leaves the
		// number visible as evidence rather than as an accusation.
		data["link_flaps_24h"] = strings.Count(out, "Event ID:")
		data["link_flaps_attributed"] = false
	}
	// WLAN disconnects (8003).
	if out, err := runTool(ctx, "wevtutil", "qe", "Microsoft-Windows-WLAN-AutoConfig/Operational",
		"/q:*[System[(EventID=8003) and TimeCreated[timediff(@SystemTime) <= "+strconv.FormatInt(window, 10)+"]]]",
		"/f:text", "/c:500"); err == nil {
		okAny = true
		data["wifi_disconnects_24h"] = strings.Count(out, "Event ID:")
	}
	// DHCP client errors (1001/1002 lease failures).
	if out, err := runTool(ctx, "wevtutil", "qe", "Microsoft-Windows-Dhcp-Client/Admin",
		"/q:"+timeQ, "/f:text", "/c:500"); err == nil {
		okAny = true
		data["dhcp_failures_24h"] = strings.Count(out, "Event ID:")
	}
	if !okAny {
		return nil, run.SkipError{ReasonText: "event logs not readable at this privilege"}
	}
	return data, nil
}

// ------------------------------------------------------------- ad_state (L7)

type winADCollector struct{}

func (winADCollector) Name() string      { return "ad_state" }
func (winADCollector) Privilege() string { return schema.PrivUnprivileged }

func (winADCollector) Collect(ctx context.Context) (map[string]any, error) {
	out, err := runTool(ctx, "dsregcmd", "/status")
	if err != nil {
		return nil, run.SkipError{ReasonText: "dsregcmd unavailable: " + err.Error()}
	}
	joined, azure, realm := DsregcmdState(out)
	data := map[string]any{
		"ad_domain_joined": joined,
		"ad_azure_joined":  azure,
	}
	if realm != "" {
		data["ad_realm"] = realm
	}
	// Is this machine itself a DC? The NTDS service key exists only on
	// domain controllers, and a DC has no member-style secure channel to
	// itself — sc_query "fails" there while the domain is perfectly healthy
	// (field-run lesson from a freshly promoted DC).
	if _, err := runTool(ctx, "reg", "query",
		`HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters`); err == nil {
		data["ad_is_dc"] = true
	}

	// Secure channel (read-only), MEMBER machines only. Two field lessons are
	// baked in here, and they pull in opposite directions:
	//
	//  1. Never judge nltest by its output TEXT — it speaks the OS language
	//     (French-Windows run).
	//  2. But /sc_query answers from the EXISTING session: after the computer
	//     account password was reset on the DC, /sc_query still reported
	//     success, Test-ComputerSecureChannel still returned True, and this
	//     check printed a confident "trust intact" while the trust was in
	//     fact broken (Win 11 member run). A check that can be answered from
	//     cache is not a measurement.
	//
	// So: /sc_verify forces a fresh authentication, and its verdict is read
	// from the NUMERIC status in the body — because nltest prints
	// "Trust Verification Status = 86 0x56 ERROR_INVALID_PASSWORD" and then
	// EXITS ZERO. Numbers survive translation; exit codes do not carry it.
	if joined && realm != "" && data["ad_is_dc"] != true {
		verifyOut, verifyErr := runTool(ctx, "nltest", "/sc_verify:"+realm)
		switch statuses := nltestStatuses(verifyOut); {
		case len(statuses) > 0:
			ok := true
			for _, code := range statuses {
				if code != 0 {
					ok = false
					data["ad_secure_channel_error"] = fmt.Sprintf("0x%X", code)
				}
			}
			data["ad_secure_channel_ok"] = ok
			data["ad_secure_channel_probe"] = "sc_verify"
			// The verify ran and returned a real status, so this result IS
			// evidence — unless something the collector cannot see (a clock
			// outside Kerberos tolerance) invalidates it, in which case the
			// triage layer flips this to false before the KB is evaluated.
			data["ad_secure_channel_verifiable"] = true
		case verifyErr == nil:
			// Ran, but no status line we could parse: do NOT invent a green.
			data["ad_secure_channel_probe"] = "sc_verify (unparsed)"
		default:
			if _, isExit := verifyErr.(*exec.ExitError); isExit {
				data["ad_secure_channel_ok"] = false
				data["ad_secure_channel_probe"] = "sc_verify (exit code)"
			} // nltest missing → fact honestly absent
		}
	}
	return data, nil
}

// ------------------------------------------------------------- firewall (L4)

type winFirewallCollector struct{}

func (winFirewallCollector) Name() string      { return "firewall" }
func (winFirewallCollector) Privilege() string { return schema.PrivUnprivileged }

func (winFirewallCollector) Collect(ctx context.Context) (map[string]any, error) {
	out, err := runTool(ctx, "netsh", "advfirewall", "show", "allprofiles")
	if err != nil {
		return nil, run.SkipError{ReasonText: "netsh advfirewall unavailable: " + err.Error()}
	}
	active := strings.Count(out, "ON") > 0
	inbound := "accept"
	if strings.Contains(out, "BlockInbound") {
		inbound = "drop"
	}
	return map[string]any{
		"firewall_tool":         "windows-advfirewall",
		"firewall_active":       active,
		"firewall_input_policy": inbound,
		// Per-rule reconciliation against listeners needs `netsh advfirewall
		// firewall show rule name=all` parsing — Windows-remaining.
	}, nil
}
