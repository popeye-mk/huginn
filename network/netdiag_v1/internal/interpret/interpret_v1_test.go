package interpret

import (
	"strings"
	"testing"
)

// Fixture-per-rule (§16.1): every v1 seed rule fires on its crafted facts and
// stays silent when the facts are healthy or absent.
func TestV1RuleFixtures(t *testing.T) {
	rules, _, err := LoadRules("")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		rule  string
		facts map[string]any
	}{
		{"link_down", map[string]any{"link_up": false}},
		{"duplex_mismatch", map[string]any{"link_duplex": "half"}},
		{"link_errors", map[string]any{"link_error_rate_pct": 2.5}},
		{"link_flap_history", map[string]any{"link_flaps_24h": 14, "link_flaps_attributed": true}},
		{"wifi_weak_signal", map[string]any{"wifi_signal_dbm": -82.0}},
		{"nic_power_saving", map[string]any{"nic_power_saving": true}},
		{"gateway_arp_unresolved", map[string]any{"gateway_arp_state": "incomplete"}},
		{"apipa_no_dhcp", map[string]any{"apipa_only": true}},
		{"no_default_route", map[string]any{"default_route_present": false, "has_ipv4_global": true}},
		{"default_route_conflict", map[string]any{"default_route_conflict": true}},
		{"gateway_unreachable", map[string]any{"gateway_reachable": false}},
		{"gateway_lossy", map[string]any{"gateway_reachable": true, "gateway_loss_pct": 40}},
		{"upstream_unreachable", map[string]any{"gateway_reachable": true, "upstream_reachable": false}},
		{"upstream_lossy", map[string]any{"upstream_loss_pct": 25, "gateway_loss_pct": 0}},
		{"high_jitter", map[string]any{"upstream_jitter_ms": 55.2}},
		{"path_mtu_low", map[string]any{"path_mtu": 1280}},
		{"ipv6_broken_dualstack", map[string]any{"ipv6_global_present": true, "ipv6_path_ok": false}},
		{"vpn_full_tunnel", map[string]any{"vpn_default_route": true}},
		{"vpn_debris", map[string]any{"vpn_debris_count": 1}},
		{"high_retransmit_ratio", map[string]any{"tcp_retrans_pct": 8.1}},
		{"tcp_reset_storm", map[string]any{"tcp_resets_per_1k": 250}},
		{"dns_resolution_failure", map[string]any{"dns_resolution_ok": false}},
		{"no_dns_servers", map[string]any{"dns_servers_count": 0}},
		{"dns_slow", map[string]any{"dns_resolution_ok": true, "dns_latency_ms": 900}},
		{"dns_hijack", map[string]any{"dns_public_name_private_ip": true}},
		{"resolver_disagreement", map[string]any{"resolvers_disagree": true}},
		{"hosts_file_override", map[string]any{"hosts_override_count": 2}},
		{"captive_portal", map[string]any{"captive_portal_detected": true}},
		{"proxy_unreachable", map[string]any{"proxy_configured": true, "proxy_reachable": false}},
		{"clock_skew", map[string]any{"ntp_offset_ms": 300000}},
		{"no_time_sync", map[string]any{"time_sync_configured": false}},
		{"doh_bypass_active", map[string]any{"doh_connections_active": true}},
		{"browser_doh_enabled", map[string]any{"browser_doh": "enabled"}},
		{"dnssec_not_validating", map[string]any{"dnssec_validating": false}},
		{"pac_unusable", map[string]any{"pac_url_configured": true, "pac_valid": false}},
		{"tls_inspection_ca", map[string]any{"tls_inspection_ca_suspected": true}},
		{"firewall_blocking_listeners", map[string]any{"firewall_blocked_listener_count": 2}},
		{"wifi_channel_congested", map[string]any{"wifi_cochannel_aps": 5}},
		{"dot1x_auth_failed", map[string]any{"dot1x_active": true, "dot1x_eap_state": "FAILURE"}},
		{"ad_dns_public_resolver", map[string]any{"dns_public_resolver_only": true, "ad_srv_resolved": false}},
		{"ad_dc_clock_skew", map[string]any{"ad_dc_clock_offset_ms": 400000}},
		{"ad_secure_channel_broken", map[string]any{"ad_secure_channel_ok": false, "ad_secure_channel_verifiable": true}},
		{"ad_dcs_unreachable", map[string]any{"ad_srv_resolved": true, "ad_dcs_responding": 0}},
		{"print_spooler_stopped", map[string]any{"spooler_running": false}},
		{"print_queue_jammed", map[string]any{"print_jobs_errored": 3}},
		{"print_queue_stale", map[string]any{"print_jobs_stuck_15min": 2}},
		{"target_name_unresolved", map[string]any{"target_resolved": false}},
		{"hygiene_poisoning_surface", map[string]any{"hygiene_poisoning_exposed": true}},
		{"hygiene_risky_listeners", map[string]any{"hygiene_risky_listener_count": 2}},
		{"hygiene_smb1_enabled", map[string]any{"hygiene_smb1_enabled": true}},
		{"hygiene_rdp_without_nla", map[string]any{"hygiene_rdp_nla": false}},
		// L2 (0.9.14). The medium guard on link_negotiated_low_wired is the
		// point of that rule: see selftest for the Wi-Fi negative case.
		{"link_negotiated_low_wired", map[string]any{
			"link_primary_is_wireless": false, "link_medium_confirmed": true,
			"link_up": true, "link_speed_mbps": 10}},
		{"dot1x_port_unauthorized", map[string]any{
			"dot1x_active": true, "dot1x_port_status": "Unauthorized"}},
		{"neigh_mostly_incomplete", map[string]any{
			"neigh_entry_count": 12, "neigh_incomplete_pct": 90}},
		{"wifi_open_network", map[string]any{"wifi_key_mgmt": "NONE"}},
		// Bug #31: flaps only accuse the machine's own link when they were
		// ATTRIBUTED to it.
		{"idle_iface_flapping", map[string]any{"link_flaps_other_total": 46}},
	}
	covered := map[string]bool{}
	for _, c := range cases {
		covered[c.rule] = true
		if !fires(rules, c.rule, c.facts) {
			t.Errorf("rule %s did not fire on its fixture", c.rule)
		}
	}
	// Every embedded rule has a fixture — no untested rules sneak in.
	for _, r := range rules {
		if !covered[r.ID] {
			t.Errorf("rule %s has no fixture in this test", r.ID)
		}
	}
	// Absence is never health: empty facts fire nothing.
	if got := Evaluate(rules, map[string]any{}); len(got) != 0 {
		t.Errorf("rules fired on empty facts: %v", got)
	}
}

// Repro-or-tagged rule (§16.1): every embedded KB entry must declare its
// reproduction: a scripted namespace/netem scenario or an honest
// hardware-only tag.
func TestEmbeddedRulesCarryRepro(t *testing.T) {
	rules, _, err := LoadRules("")
	if err != nil {
		t.Fatal(err)
	}
	valid := map[string]bool{"namespace": true, "netem": true, "hardware-only": true}
	for _, r := range rules {
		if !valid[r.Repro] {
			t.Errorf("rule %s: repro tag %q is not namespace/netem/hardware-only", r.ID, r.Repro)
		}
	}
}

// §6.2: --for-user costs a second template per KB entry — so every embedded
// entry must actually carry one.
func TestEmbeddedRulesCarryForUser(t *testing.T) {
	rules, _, err := LoadRules("")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if len(r.ForUser) < 40 {
			t.Errorf("rule %s: for_user template missing or too thin", r.ID)
		}
	}
}

func fires(rules []Rule, id string, facts map[string]any) bool {
	for _, f := range Evaluate(rules, facts) {
		if f.ID == id {
			return true
		}
	}
	return false
}

// Bug #30 (Zorin Wi-Fi, 0.9.20): link_flaps_24h counts "link is down" and
// "carrier lost", which is exactly what a Wi-Fi disconnect logs. The rule's
// advice was written for copper, so a laptop with no ethernet port at all was
// told to check its cable and switch port.
//
// The fix is wording, not matching — see rules.json for why a medium-split
// would have been worse. These assertions pin the wording, because wording is
// the entire fix and nothing else would catch it regressing.
func TestLinkFlapAdviceFitsBothMedia(t *testing.T) {
	rules, _, err := LoadRules("")
	if err != nil {
		t.Fatal(err)
	}
	var flap *Rule
	for i := range rules {
		if rules[i].ID == "link_flap_history" {
			flap = &rules[i]
		}
	}
	if flap == nil {
		t.Fatal("link_flap_history is gone")
	}

	// It must still fire on a wireless machine — silence would be worse.
	if !fires(rules, "link_flap_history", map[string]any{
		"link_primary_is_wireless": true, "link_flaps_24h": 21, "link_flaps_attributed": true,
	}) {
		t.Error("did not fire on a Wi-Fi machine with 21 disconnects")
	}
	if !fires(rules, "link_flap_history", map[string]any{
		"link_primary_is_wireless": false, "link_flaps_24h": 21, "link_flaps_attributed": true,
	}) {
		t.Error("did not fire on a wired machine")
	}
	// …and on a machine whose medium is unknown, which is why this is one
	// rule rather than two.
	if !fires(rules, "link_flap_history", map[string]any{
		"link_flaps_24h": 21, "link_flaps_attributed": true,
	}) {
		t.Error("did not fire when the medium is unknown — 21 drops and silence is the worst outcome")
	}
	// Bug #31: but it must NOT fire when the flaps could not be attributed to
	// the interface in use. 46 flaps of an unplugged port is not this
	// machine's connection dropping.
	if fires(rules, "link_flap_history", map[string]any{
		"link_flaps_24h": 46, "link_flaps_attributed": false,
	}) {
		t.Error("accused the machine's link using flaps that were never attributed to it")
	}

	for _, text := range []string{flap.NextStep, flap.ForUser} {
		lower := strings.ToLower(text)
		if !strings.Contains(lower, "wi-fi") {
			t.Errorf("advice never mentions Wi-Fi, so it reads as cable-only:\n%s", text)
		}
		if !strings.Contains(lower, "cable") {
			t.Errorf("advice dropped the wired case entirely:\n%s", text)
		}
		// The original sin: naming a cable as THE cause rather than one of two.
		for _, wrong := range []string{"check cable and switch port", "points to a loose cable"} {
			if strings.Contains(lower, wrong) {
				t.Errorf("advice still asserts a wired cause unconditionally: %q", wrong)
			}
		}
	}
}
