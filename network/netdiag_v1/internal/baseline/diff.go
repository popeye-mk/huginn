// The interpreted diff engine (§5.2/§7.1): not a raw JSON diff — only the
// differences a heuristic considers diagnostic, ranked by severity, with
// known-benign deltas (hostnames, timestamps, counters-since-boot)
// deliberately ignored and honestly listed as ignored.
package baseline

import (
	"fmt"
	"sort"
	"strings"
)

// Change is one diagnostic difference.
type Change struct {
	Field    string `json:"field"`
	Old      string `json:"old"`
	New      string `json:"new"`
	Severity string `json:"severity"` // critical | warning | info
	Note     string `json:"note"`
}

// identityWatch: facts whose CHANGE is itself the signal.
var identityWatch = []struct {
	key, note, severity string
}{
	{"gateway_mac", "gateway MAC changed — replaced router, or the ARP-spoof signal (§5.2)", "critical"},
	{"dhcp_server", "DHCP server changed — rogue-DHCP signal if nobody changed the network", "critical"},
	{"default_route_present", "default route presence changed", "critical"},
	{"gateway_ip", "default gateway changed", "warning"},
	{"dns_servers", "DNS servers changed", "warning"},
	{"path_mtu", "path MTU changed — a tunnel appeared or disappeared on the route", "warning"},
	{"captive_portal_detected", "captive-portal interception state changed", "warning"},
	{"resolvers_disagree", "resolver-disagreement state changed", "warning"},
	{"firewall_input_policy", "firewall input policy changed", "warning"},
	{"proxy_configured", "proxy configuration changed", "warning"},
	{"dnssec_validating", "DNSSEC validation state changed", "info"},
	{"vpn_default_route", "full-tunnel VPN state changed", "info"},
	{"wifi_ssid", "connected SSID changed", "info"},
	{"wifi_bssid", "serving AP (BSSID) changed — roamed or AP replaced", "info"},
	{"wifi_channel", "Wi-Fi channel changed", "info"},
	{"link_speed_mbps", "negotiated link speed changed", "warning"},
	{"link_duplex", "negotiated duplex changed", "critical"},
	{"browser_doh", "browser DoH configuration changed", "info"},
	{"ipv6_path_ok", "IPv6 path health changed", "warning"},
	{"dot1x_eap_state", "802.1X EAP state changed", "warning"},
}

// regressionWatch: numeric facts where only WORSENING is diagnostic.
// worse(old,new) returns a note when new is meaningfully worse.
var regressionWatch = []struct {
	key      string
	severity string
	worse    func(old, new float64) string
}{
	{"upstream_loss_pct", "warning", func(o, n float64) string {
		if n > o+10 {
			return fmt.Sprintf("upstream loss regressed: %.0f%% → %.0f%%", o, n)
		}
		return ""
	}},
	{"gateway_loss_pct", "warning", func(o, n float64) string {
		if n > o+10 {
			return fmt.Sprintf("gateway loss regressed: %.0f%% → %.0f%%", o, n)
		}
		return ""
	}},
	{"upstream_rtt_avg_ms", "warning", func(o, n float64) string {
		if n > o*2+10 {
			return fmt.Sprintf("upstream latency regressed: %.1f ms → %.1f ms (beyond this location's normal)", o, n)
		}
		return ""
	}},
	{"gateway_q_rtt_avg_ms", "warning", func(o, n float64) string {
		if n > o*2+5 {
			return fmt.Sprintf("gateway latency regressed: %.1f ms → %.1f ms", o, n)
		}
		return ""
	}},
	{"upstream_jitter_ms", "warning", func(o, n float64) string {
		if n > o*2+15 {
			return fmt.Sprintf("jitter regressed: %.1f ms → %.1f ms", o, n)
		}
		return ""
	}},
	{"dns_latency_ms", "warning", func(o, n float64) string {
		if n > o*3+50 {
			return fmt.Sprintf("DNS answer time regressed: %.0f ms → %.0f ms", o, n)
		}
		return ""
	}},
	{"wifi_signal_dbm", "warning", func(o, n float64) string {
		if n < o-15 {
			return fmt.Sprintf("Wi-Fi signal dropped: %.0f dBm → %.0f dBm", o, n)
		}
		return ""
	}},
	{"tcp_retrans_pct", "warning", func(o, n float64) string {
		if n > o+5 {
			return fmt.Sprintf("TCP retransmit ratio regressed: %.1f%% → %.1f%%", o, n)
		}
		return ""
	}},
	{"wifi_cochannel_aps", "info", func(o, n float64) string {
		if n > o+3 {
			return fmt.Sprintf("channel got busier: %.0f → %.0f co-channel APs", o, n)
		}
		return ""
	}},
}

// ignoredBenign is what the interpreter deliberately does not diff — stated
// in the output per §7.1's honest-limits rule.
const IgnoredBenign = "hostnames, MAC of this machine, lease timestamps, since-boot counters, socket counts, event-history counts, probe targets"

// Diff computes the interpreted delta from old (baseline / good) to new
// (current / bad).
func Diff(oldFacts, newFacts map[string]any) []Change {
	var out []Change
	for _, w := range identityWatch {
		ov, oOK := oldFacts[w.key]
		nv, nOK := newFacts[w.key]
		if !oOK && !nOK {
			continue
		}
		os, ns := fmtVal(ov), fmtVal(nv)
		if os == ns {
			continue
		}
		out = append(out, Change{w.key, os, ns, w.severity, w.note})
	}
	for _, w := range regressionWatch {
		o, oOK := toF(oldFacts[w.key])
		n, nOK := toF(newFacts[w.key])
		if !oOK || !nOK {
			continue // regression needs both sides measured — absence is never drift
		}
		if note := w.worse(o, n); note != "" {
			out = append(out, Change{w.key, fmtVal(oldFacts[w.key]), fmtVal(newFacts[w.key]), w.severity, note})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return sevRank(out[i].Severity) > sevRank(out[j].Severity)
	})
	return out
}

// Render prints the drift report. header names the comparison
// ("baseline saved 2h ago" / "good.json → bad.json").
func Render(changes []Change, header string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  Drift: %s\n  %s\n", header, strings.Repeat("─", 62))
	if len(changes) == 0 {
		b.WriteString("  No diagnostic drift — the compared states match within thresholds.\n")
	} else {
		for i, c := range changes {
			fmt.Fprintf(&b, "  %d. [%s] %s: %s → %s\n     %s\n",
				i+1, c.Severity, c.Field, c.Old, c.New, c.Note)
		}
		// Ranked verdict: the top change is where to start (§7.1).
		fmt.Fprintf(&b, "\n  Start with #1 (%s) — it is the highest-ranked difference.\n", changes[0].Field)
	}
	fmt.Fprintf(&b, "\n  Deliberately ignored (known-benign): %s.\n", IgnoredBenign)
	return b.String()
}

func fmtVal(v any) string {
	switch t := v.(type) {
	case nil:
		return "(absent)"
	case []string:
		return strings.Join(t, ",")
	case []any:
		parts := make([]string, len(t))
		for i, x := range t {
			parts[i] = fmt.Sprintf("%v", x)
		}
		return strings.Join(parts, ",")
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%.1f", t)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func toF(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case float64:
		return n, true
	}
	return 0, false
}

func sevRank(s string) int {
	switch s {
	case "critical":
		return 3
	case "warning":
		return 2
	}
	return 1
}
