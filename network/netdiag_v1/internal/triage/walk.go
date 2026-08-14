// The symptom-driven layer walk (§6): one engine, target-aware presets.
// Each profile is an ordered list of checks over facts; a check on an
// unmeasured fact reports "not measured", never a fake green.
package triage

import (
	"fmt"
	"strings"

	"netdiag/internal/interpret"
)

// Check is one line of a walk: which layer vouches, what was asked, and a
// verdict function over the facts.
type Check struct {
	Layer string
	What  string
	Eval  func(f map[string]any) (status, detail string) // status: ok/fail/skip
}

// Profile is a symptom preset.
type Profile struct {
	Name    string
	DCLabel string // renames the blame table's 4th segment (cant-login)
	Layers  map[string]bool
	Checks  []Check
	Prepare func(facts map[string]any, arg string) // target probes etc.
}

// PruneMedium implements the interactive pruning answer (§6 / v5 §7):
// "Wired or Wi-Fi?" removes the whole irrelevant branch in one keystroke.
func (p Profile) PruneMedium(medium string) Profile {
	var kept []Check
	for _, c := range p.Checks {
		w := strings.ToLower(c.What)
		wifiCheck := strings.Contains(w, "wi-fi") || strings.Contains(w, "wireless") ||
			strings.Contains(w, "signal")
		wiredCheck := strings.Contains(w, "duplex")
		switch medium {
		case "wired":
			if wifiCheck {
				continue
			}
		case "wifi":
			if wiredCheck {
				continue
			}
		}
		kept = append(kept, c)
	}
	p.Checks = kept
	return p
}

// FirstBreak returns the first failing check as a one-line description, or ""
// when the walk is clean. Callers use it to correct the §8 verdict: the blame
// partition only measures the transport path, so a pure config/service fault
// (bad resolver, missing SRV record) leaves every segment green while the walk
// is red — field-run lesson: the headline must not say "nothing is visible
// from this machine" when the walk found a certain break.
func (p Profile) FirstBreak(facts map[string]any) string {
	for _, c := range p.Checks {
		if status, detail := c.Eval(facts); status == "fail" {
			// Bug #27 (Zorin, 0.9.18): check labels are written as ASSERTIONS
			// ("path MTU sane", "IPv6 not half-broken") because they read well
			// beside a ✓. Pasted into a verdict after a ✗ they invert: "path
			// MTU sane — 1380 — tunnel-grade" tells the reader the MTU is fine
			// in the same breath as saying it is not.
			//
			// The failure DETAIL already carries the whole meaning, so the
			// verdict leads with it and keeps the label as the subject.
			return breakLine(c.Layer, c.What, detail)
		}
	}
	return ""
}

// breakLine renders a FAILED check as a sentence.
//
// Check labels are written as assertions ("path MTU sane", "IPv6 not
// half-broken") because they read correctly beside a ✓. After a ✗ they invert:
// "path MTU sane — 1380 — tunnel-grade" tells the reader the MTU is fine in
// the same breath as saying it is not. The detail carries the meaning, so the
// detail leads and the label becomes the name of the check that failed.
func breakLine(layer, what, detail string) string {
	return fmt.Sprintf("%s %s failed — %s", layer, what, detail)
}

// Walk runs the profile checks and renders the §6-style report section.
func (p Profile) Walk(facts map[string]any, findings []interpret.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  why %s — layer walk\n", p.Name)
	b.WriteString("  " + strings.Repeat("─", 62) + "\n")
	var firstFail string
	for _, c := range p.Checks {
		status, detail := c.Eval(facts)
		mark := map[string]string{"ok": "✓", "fail": "✗", "skip": "–"}[status]
		fmt.Fprintf(&b, "  %-4s%-34s %s  %s\n", c.Layer, c.What, mark, detail)
		if status == "fail" && firstFail == "" {
			// Bug #27 half-fixed in 0.9.19: the VERDICT was corrected and this
			// line, which says the same thing four rows lower, was not. Both
			// now go through breakLine so they cannot disagree again.
			firstFail = breakLine(c.Layer, c.What, detail)
		}
	}
	b.WriteString("\n")
	if firstFail != "" {
		fmt.Fprintf(&b, "  First break in the walk → %s\n\n", firstFail)
	} else {
		b.WriteString("  The walk found no break in the measured layers.\n\n")
	}
	// Findings pruned to the layers this symptom cares about.
	var kept []interpret.Finding
	for _, f := range findings {
		if p.Layers[f.Layer] {
			kept = append(kept, f)
		}
	}
	if len(kept) > 0 {
		fmt.Fprintf(&b, "  Related findings (%d)\n", len(kept))
		for i, f := range kept {
			fmt.Fprintf(&b, "  %d. [%s|%s|%s] %s\n", i+1, f.Layer, f.Severity, f.Confidence, f.Finding)
			if f.NextStep != "" {
				fmt.Fprintf(&b, "     → %s\n", f.NextStep)
			}
			fmt.Fprintf(&b, "     (rule: %s)\n", f.ID)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// ---- shared check builders ----

func boolCheck(layer, what, key string, wantTrue bool, okD, failD, skipD string) Check {
	return Check{layer, what, func(f map[string]any) (string, string) {
		v, present := f[key]
		if !present {
			return "skip", skipD
		}
		if v == wantTrue {
			return "ok", okD
		}
		return "fail", failD
	}}
}

// ---- the profiles ----

// Profiles returns the registry; arg is the target/domain where relevant.
func Profiles() map[string]Profile {
	return map[string]Profile{
		"no-internet":  noInternet(),
		"slow":         slow(),
		"wifi":         wifi(),
		"intermittent": intermittent(),
		"cant-reach":   cantReach(),
		"cant-print":   cantPrint(),
		"cant-rdp":     cantRDP(),
		"cant-login":   cantLogin(),
	}
}

func noInternet() Profile {
	return Profile{
		Name:   "no-internet",
		Layers: map[string]bool{"L1": true, "L2": true, "L3": true, "L7": true},
		Checks: []Check{
			boolCheck("L1", "a link is up", "link_up", true,
				"an interface is up", "no interface is up at all", "not measured"),
			boolCheck("L3", "real (non-APIPA) address", "apipa_only", false,
				"a real address is assigned", "APIPA only — DHCP never answered", "not measured"),
			boolCheck("L3", "default route exists", "default_route_present", true,
				"default route present", "no default route", "not measured"),
			{"L2", "gateway answers ARP", func(f map[string]any) (string, string) {
				switch str(f["gateway_arp_state"]) {
				case "resolved":
					return "ok", "MAC resolved"
				case "incomplete":
					return "fail", "never resolves — dead/wrong gateway or VLAN mismatch"
				case "absent":
					return "skip", "not in cache yet (no traffic has tried)"
				}
				return "skip", "not measured"
			}},
			boolCheck("L3", "gateway answers ping", "gateway_reachable", true,
				"gateway answers", "gateway does not answer", "not measured (skipped)"),
			boolCheck("L3", "internet past the gateway", "upstream_reachable", true,
				"public anchor answers", "nothing past the gateway answers", "not measured"),
			boolCheck("L7", "DNS resolves a known-good name", "dns_resolution_ok", true,
				"resolution works", "resolution fails", "not measured"),
			boolCheck("L7", "no portal in the way", "captive_portal_detected", false,
				"the 204 probe came back clean", "a captive portal/middlebox intercepts HTTP", "probe did not complete"),
		},
	}
}

func slow() Profile {
	p := Profile{
		Name:   "slow",
		Layers: map[string]bool{"L1": true, "L3": true, "L4": true, "L7": true},
		Checks: []Check{
			{"L1", "duplex negotiated full", func(f map[string]any) (string, string) {
				d, ok := f["link_duplex"].(string)
				if !ok {
					return "skip", "not exposed by this NIC"
				}
				if d == "half" {
					return "fail", "half-duplex — this alone explains severe slowness"
				}
				return "ok", d + "-duplex"
			}},
			{"L1", "Wi-Fi signal adequate", func(f map[string]any) (string, string) {
				v, present := f["wifi_signal_dbm"]
				if !present {
					return "skip", "wired or not exposed"
				}
				if num(v) < -75 {
					return "fail", fmt.Sprintf("%.0f dBm — weak", num(v))
				}
				return "ok", fmt.Sprintf("%.0f dBm", num(v))
			}},
			{"L3", "loss to gateway", lossCheck("gateway_loss_pct", 20)},
			{"L3", "loss past the gateway", lossCheck("upstream_loss_pct", 10)},
			{"L3", "latency stability (jitter)", func(f map[string]any) (string, string) {
				v, present := f["upstream_jitter_ms"]
				if !present {
					return "skip", "not measured"
				}
				if num(v) > 30 {
					return "fail", fmt.Sprintf("%.0f ms jitter — calls will stutter", num(v))
				}
				return "ok", fmt.Sprintf("%.1f ms", num(v))
			}},
			{"L3", "path MTU sane", func(f map[string]any) (string, string) {
				v, present := f["path_mtu"]
				if !present {
					return "skip", "not measured"
				}
				if num(v) < 1400 {
					return "fail", fmt.Sprintf("%d — tunnel-grade; large packets may black-hole", int(num(v)))
				}
				return "ok", fmt.Sprintf("%d", int(num(v)))
			}},
			{"L3", "IPv6 not half-broken", func(f map[string]any) (string, string) {
				if f["ipv6_global_present"] == true && f["ipv6_path_ok"] == false {
					return "fail", "v6 configured but dead — timeout-then-fallback tax on every connect"
				}
				if f["ipv6_global_present"] == false {
					return "ok", "no v6 configured (nothing to fall back from)"
				}
				if f["ipv6_path_ok"] == true {
					return "ok", "dual stack healthy"
				}
				return "skip", "not measured"
			}},
			{"L4", "TCP retransmission ratio", func(f map[string]any) (string, string) {
				v, present := f["tcp_retrans_pct"]
				if !present {
					return "skip", "counters unavailable"
				}
				if num(v) > 5 {
					return "fail", fmt.Sprintf("%.1f%% retransmits since boot — measured lossy path", num(v))
				}
				return "ok", fmt.Sprintf("%.1f%%", num(v))
			}},
			{"L7", "DNS answer time", func(f map[string]any) (string, string) {
				v, present := f["dns_latency_ms"]
				if !present {
					return "skip", "resolution failed or unmeasured"
				}
				if num(v) > 500 {
					return "fail", fmt.Sprintf("%d ms per lookup — every new connection pays this", int(num(v)))
				}
				return "ok", fmt.Sprintf("%d ms", int(num(v)))
			}},
		},
	}
	return p
}

func wifi() Profile {
	return Profile{
		Name:   "wifi",
		Layers: map[string]bool{"L1": true, "L2": true, "L3": true},
		Checks: []Check{
			boolCheck("L1", "wireless interface present", "wifi_present", true,
				"present", "no wireless interface", "driver exposes nothing at /proc/net/wireless"),
			{"L1", "signal strength", func(f map[string]any) (string, string) {
				v, present := f["wifi_signal_dbm"]
				if !present {
					return "skip", "not exposed (SSID/channel detail needs nl80211 — v1-remaining)"
				}
				if num(v) < -75 {
					return "fail", fmt.Sprintf("%.0f dBm — weak; drops and low rates expected", num(v))
				}
				return "ok", fmt.Sprintf("%.0f dBm", num(v))
			}},
			{"L1", "channel occupancy", func(f map[string]any) (string, string) {
				v, present := f["wifi_cochannel_aps"]
				if !present {
					return "skip", "scan cache unreadable (needs root/netdev for wpa_ctrl)"
				}
				if num(v) > 3 {
					return "fail", fmt.Sprintf("%d other APs on this channel — airtime contention", int(num(v)))
				}
				return "ok", fmt.Sprintf("%d co-channel, %d adjacent", int(num(v)), int(num(f["wifi_adjacent_aps"])))
			}},
			{"L2", "802.1X authentication", func(f map[string]any) (string, string) {
				if f["dot1x_active"] != true {
					return "ok", "not an 802.1X network"
				}
				if str(f["dot1x_eap_state"]) == "FAILURE" {
					return "fail", "EAP FAILURE — credentials/certificate rejected"
				}
				if str(f["dot1x_eap_state"]) == "SUCCESS" {
					return "ok", "EAP authenticated"
				}
				return "skip", "EAP state not readable"
			}},
			{"L1", "disconnect history (24 h)", func(f map[string]any) (string, string) {
				v, present := f["wifi_disconnects_24h"]
				if !present {
					return "skip", "journal not readable"
				}
				if num(v) > 5 {
					return "fail", fmt.Sprintf("%d disconnects logged — roaming thrash or interference", int(num(v)))
				}
				return "ok", fmt.Sprintf("%d logged", int(num(v)))
			}},
			{"L1", "NIC power saving", func(f map[string]any) (string, string) {
				v, present := f["nic_power_saving"]
				if !present {
					return "skip", "not exposed"
				}
				if v == true {
					return "fail", "runtime PM may suspend the adapter when idle"
				}
				return "ok", "adapter stays awake"
			}},
			boolCheck("L3", "gateway reachable over the air", "gateway_reachable", true,
				"answers", "does not answer", "not measured"),
		},
	}
}

func intermittent() Profile {
	return Profile{
		Name:   "intermittent",
		Layers: map[string]bool{"L1": true, "L2": true, "L3": true},
		Checks: []Check{
			{"L1", "link flaps in the last 24 h", func(f map[string]any) (string, string) {
				v, present := f["link_flaps_24h"]
				if !present {
					return "skip", "journal not readable — run `watch` (v1.3) or check logs manually"
				}
				if num(v) > 5 {
					return "fail", fmt.Sprintf("%d flaps logged — the intermittent fault, caught retrospectively", int(num(v)))
				}
				return "ok", fmt.Sprintf("%d logged", int(num(v)))
			}},
			{"L1", "carrier changes since boot", func(f map[string]any) (string, string) {
				v, present := f["link_carrier_changes"]
				if !present {
					return "skip", "not exposed"
				}
				if num(v) > 20 {
					return "fail", fmt.Sprintf("%d carrier transitions — unstable physical link", int(num(v)))
				}
				return "ok", fmt.Sprintf("%d", int(num(v)))
			}},
			{"L3", "DHCP failures in the last 24 h", func(f map[string]any) (string, string) {
				v, present := f["dhcp_failures_24h"]
				if !present {
					return "skip", "journal not readable"
				}
				if num(v) > 0 {
					return "fail", fmt.Sprintf("%d logged — lease renewals failing intermittently", int(num(v)))
				}
				return "ok", "none logged"
			}},
			{"L3", "loss right now", lossCheck("gateway_loss_pct", 5)},
		},
	}
}

func lossCheck(key string, threshold float64) func(map[string]any) (string, string) {
	return func(f map[string]any) (string, string) {
		v, present := f[key]
		if !present {
			return "skip", "not measured"
		}
		if num(v) > threshold {
			return "fail", fmt.Sprintf("%.0f%% loss", num(v))
		}
		return "ok", fmt.Sprintf("%.0f%% loss", num(v))
	}
}

// ---- the cant-reach family (§6, §6.1, §6.4) ----

func targetChecks(portDesc string) []Check {
	return []Check{
		boolCheck("L3", "route/link toward the world", "default_route_present", true,
			"default route present", "no default route — nothing off-subnet is reachable", "not measured"),
		{"L7", "target resolves in DNS", func(f map[string]any) (string, string) {
			v, present := f["target_resolved"]
			if !present {
				return "skip", "no target probed"
			}
			if v == true {
				if f["target_is_ip_literal"] == true {
					return "ok", "IP literal — DNS not involved"
				}
				return "ok", fmt.Sprintf("%v", f["target_ips"])
			}
			return "fail", str(f["target_resolve_error"])
		}},
		{"L3", "target answers ping", func(f map[string]any) (string, string) {
			v, present := f["target_ping_ok"]
			if !present {
				// Distinguish "we were not allowed to ping" from "there was
				// nothing to ping": blaming privilege for an unresolvable name
				// sends the reader hunting a permissions problem that is not
				// there (field run: `why cant-print canon`).
				if f["target_resolved"] == false {
					return "skip", "nothing to ping — the name did not resolve"
				}
				return "skip", "ICMP not permitted at this privilege"
			}
			if v == true {
				return "ok", "answers"
			}
			return "fail", "no echo reply (host down or ICMP filtered — not conclusive alone)"
		}},
		{"L4", portDesc, func(f map[string]any) (string, string) {
			st, present := f["target_port_state"].(string)
			if !present {
				if f["target_resolved"] == false {
					return "skip", "no port probed — the name did not resolve, so there is no address to try"
				}
				return "skip", "no port probed"
			}
			switch st {
			case "open":
				return "ok", fmt.Sprintf("port %v answers", f["target_open_port"])
			case "refused":
				return "fail", "connection refused — the service is down or firewalled ON THE TARGET; stop looking at your network"
			default:
				return "fail", "silently dropped (filtered) — a firewall on the path or the target"
			}
		}},
	}
}

func cantReach() Profile {
	return Profile{
		Name:   "cant-reach",
		Layers: map[string]bool{"L3": true, "L4": true, "L7": true},
		Checks: targetChecks("service port open"),
		Prepare: func(f map[string]any, arg string) {
			host, ports := splitHostPorts(arg, []int{443, 80})
			probeTarget(f, host, ports)
		},
	}
}

func cantPrint() Profile {
	return Profile{
		Name:   "cant-print",
		Layers: map[string]bool{"L3": true, "L4": true, "L7": true},
		// The local half FIRST: a stopped spooler or a jammed queue makes the
		// wire irrelevant, and a tool that only probes 9100 blames the network
		// for a fault that never left the machine.
		Checks: append([]Check{
			{"L7", "print spooler is running", func(f map[string]any) (string, string) {
				v, ok := f["spooler_running"].(bool)
				if !ok {
					return "skip", "spooler state not measured on this OS"
				}
				if !v {
					return "fail", "the Print Spooler service is STOPPED — nothing can print, and no network fix will help (start it: `sc start spooler`)"
				}
				return "ok", "spooler service is running"
			}},
			{"L7", "print queue is moving", func(f map[string]any) (string, string) {
				depth, ok := intOK(f["print_queue_depth"])
				if !ok {
					return "skip", "queue not readable (PowerShell printing cmdlets absent?)"
				}
				errored, _ := intOK(f["print_jobs_errored"])
				stuck, _ := intOK(f["print_jobs_stuck_15min"])
				switch {
				case errored > 0:
					return "fail", fmt.Sprintf("%d job(s) in an error state — clear the queue before blaming the network", errored)
				case stuck > 0:
					return "fail", fmt.Sprintf("%d job(s) queued over 15 minutes — the queue is jammed", stuck)
				case depth == 0:
					return "ok", "queue is empty"
				}
				return "ok", fmt.Sprintf("%d job(s) queued, none errored or stale", depth)
			}},
		}, targetChecks("print transport (9100/IPP/LPD/SMB)")...),
		Prepare: func(f map[string]any, arg string) {
			host, ports := splitHostPorts(arg, []int{9100, 631, 515, 445})
			probeTarget(f, host, ports)
		},
	}
}

func cantRDP() Profile {
	return Profile{
		Name:   "cant-rdp",
		Layers: map[string]bool{"L3": true, "L4": true, "L7": true},
		Checks: append(targetChecks("TCP 3389 open"), Check{
			"L7", "beyond the port", func(f map[string]any) (string, string) {
				if str(f["target_port_state"]) == "open" {
					return "ok", "transport is fine — if login still fails, check NLA/cert/session-limit on the host"
				}
				return "skip", "port not open — L7 not reachable yet"
			}}),
		Prepare: func(f map[string]any, arg string) {
			host, _ := splitHostPorts(arg, nil)
			probeTarget(f, host, []int{3389})
		},
	}
}

func cantLogin() Profile {
	return Profile{
		Name:    "cant-login",
		DCLabel: "DC / domain",
		Layers:  map[string]bool{"L3": true, "L4": true, "L7": true},
		Checks: []Check{
			{"L7", "DNS fit for AD", func(f map[string]any) (string, string) {
				pub, present := f["dns_public_resolver_only"]
				if !present {
					return "skip", "resolver list not measured"
				}
				if pub == true && f["ad_srv_resolved"] != true {
					return "fail", "this machine's DNS points at a public resolver — it can NEVER find the DC; point DNS at the DC and retest before anything else"
				}
				if f["ad_srv_resolver_mismatch"] == true {
					return "fail", fmt.Sprintf("only some configured resolvers know the domain: %v — resolver order is the problem", f["ad_srv_by_resolver"])
				}
				return "ok", "configured resolvers can serve AD queries"
			}},
			{"L7", "DC-locator SRV resolves", func(f map[string]any) (string, string) {
				v, present := f["ad_srv_resolved"]
				if !present {
					return "skip", "no domain known (pass one: netdiag why cant-login corp.local)"
				}
				if v == true {
					return "ok", fmt.Sprintf("%v DC(s): %v", f["ad_dc_count"], f["ad_dcs"])
				}
				return "fail", "_ldap._tcp.dc._msdcs lookup failed on every resolver"
			}},
			{"L7", "Kerberos + GC SRV records", func(f map[string]any) (string, string) {
				k, kp := f["ad_srv_kerberos_ok"]
				g, gp := f["ad_srv_gc_ok"]
				if !kp && !gp {
					return "skip", "not queried (no domain)"
				}
				if k == true && g == true {
					return "ok", "_kerberos and _gc both resolve"
				}
				return "fail", fmt.Sprintf("kerberos=%v gc=%v — partial SRV zone (check the _msdcs zone on the DC's DNS)", k, g)
			}},
			{"L3", "discovered DCs respond", func(f map[string]any) (string, string) {
				n, present := f["ad_dcs_responding"]
				if !present {
					return "skip", "no DCs to probe"
				}
				total := f["ad_dc_count"]
				if num(n) == 0 {
					return "fail", fmt.Sprintf("0 of %v DCs answer ping — DCs down or filtered end to end", total)
				}
				return "ok", fmt.Sprintf("%v of %v answer", n, total)
			}},
			{"L3", "DC answers ping", func(f map[string]any) (string, string) {
				v, present := f["target_ping_ok"]
				if !present {
					return "skip", "no DC to probe (SRV failed) or ICMP not permitted"
				}
				if v == true {
					return "ok", "answers"
				}
				return "fail", "DC does not answer"
			}},
			{"L4", "AD port set (88/389/445/3268)", func(f map[string]any) (string, string) {
				states, present := f["target_port_states"].(map[string]string)
				if !present {
					return "skip", "no DC probed"
				}
				var bad []string
				for p, st := range states {
					if st != "open" {
						bad = append(bad, p+":"+st)
					}
				}
				if len(bad) == 0 {
					return "ok", "all answer"
				}
				return "fail", strings.Join(bad, " ")
			}},
			{"L7", "clock inside Kerberos tolerance", func(f map[string]any) (string, string) {
				// Prefer the offset measured against the DC ITSELF (§6.4);
				// fall back to the generic time-sync offset.
				v, present := f["ad_dc_clock_offset_ms"]
				src := "vs the DC's own clock"
				if !present {
					v, present = f["ntp_offset_ms"]
					src = "vs public NTP (DC not measurable)"
				}
				if !present {
					return "skip", "offset not measured"
				}
				if num(v) > 300000 {
					return "fail", fmt.Sprintf("%.0f s off %s — Kerberos tolerates ±5 min; fix time sync first", num(v)/1000, src)
				}
				return "ok", fmt.Sprintf("%.1f s offset %s", num(v)/1000, src)
			}},
			{"L7", "machine secure channel to the domain", func(f map[string]any) (string, string) {
				if f["ad_is_dc"] == true {
					return "ok", "this machine IS a domain controller — member secure channel not applicable"
				}
				// Kerberos cannot authenticate outside its clock tolerance, so
				// a failed verify while the clock is off says nothing about the
				// trust itself (field run: a freshly REPAIRED trust reported
				// 0x5 ACCESS_DENIED purely because the clock was 10 min out).
				// Telling the technician to reset the machine trust here would
				// point away from the real cause — and cost a rejoin.
				if f["ad_secure_channel_verifiable"] == false {
					return "skip", "cannot be verified while the clock is outside Kerberos tolerance — fix the clock first, then re-check this"
				}
				v, present := f["ad_secure_channel_ok"]
				if !present {
					// A cached "success" is not a measurement: if the probe
					// could not VERIFY, say so instead of showing green.
					if p := str(f["ad_secure_channel_probe"]); p != "" {
						return "skip", "ran but could not be verified (" + p + ")"
					}
					return "skip", "not measured (Windows: nltest /sc_verify)"
				}
				if v == true {
					return "ok", "trust verified (fresh authentication, not a cached session)"
				}
				detail := "secure channel BROKEN — reset the machine trust; stop looking at the network"
				if code := str(f["ad_secure_channel_error"]); code != "" {
					if code == "0x56" { // ERROR_INVALID_PASSWORD
						detail = "machine account password no longer matches the DC (0x56) — " +
							"repair the trust: Test-ComputerSecureChannel -Repair; the network itself is fine"
					} else {
						detail += " (nltest status " + code + ")"
					}
				}
				return "fail", detail
			}},
			{"L7", "machine knows a realm", func(f map[string]any) (string, string) {
				if f["ad_domain_joined"] == true {
					return "ok", fmt.Sprintf("realm %v", f["ad_realm"])
				}
				if _, present := f["ad_domain_joined"]; !present {
					return "skip", "not measured"
				}
				return "fail", "no realm/join evidence on this machine (secure-channel check is Windows-collector work)"
			}},
		},
		Prepare: func(f map[string]any, arg string) {
			domain := arg
			if domain == "" {
				domain = str(f["ad_realm"])
			}
			if domain == "" {
				return // SRV check will honestly skip
			}
			if dc := probeADSRV(f, strings.ToLower(domain)); dc != "" {
				probeTarget(f, dc, []int{88, 389, 445, 3268})
			}
		},
	}
}

func splitHostPorts(arg string, def []int) (string, []int) {
	if i := strings.LastIndex(arg, ":"); i > 0 && !strings.Contains(arg, "]") {
		var p int
		if _, err := fmt.Sscanf(arg[i+1:], "%d", &p); err == nil {
			return arg[:i], []int{p}
		}
	}
	return arg, def
}
