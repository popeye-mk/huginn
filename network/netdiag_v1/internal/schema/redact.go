// Redaction (§4.3): --anon masks addresses, MACs (OUI kept), hostnames and
// resolver answers before a snapshot leaves the machine. Redaction is a
// security control, not a feature: redact_test.go fails the build's test run
// if a fact key exists with no redaction decision recorded here.
package schema

import (
	"fmt"
	"net"
	"strings"
)

// Redaction actions.
const (
	Keep    = "keep"     // value carries no site-identifying information
	MaskIP  = "mask_ip"  // public IPs masked, RFC1918 kept (they identify nothing off-site)
	MaskMAC = "mask_mac" // OUI (vendor) kept, host bits masked
	Drop    = "drop"     // value removed entirely under --anon
)

// RedactionPolicy records the decision for every fact key any collector can
// emit. A new fact key without an entry here fails TestRedactionPolicyCovers.
var RedactionPolicy = map[string]string{
	// link
	"link_up": Keep, "link_interface_count": Keep, "link_interfaces": Drop,
	"link_primary_interface": Keep, "link_mtu": Keep, "link_duplex": Keep,
	"link_speed_mbps": Keep, "link_rx_errors": Keep, "link_tx_errors": Keep,
	"link_error_rate_pct": Keep, "link_carrier_changes": Keep,
	"link_primary_is_wireless": Keep, "link_medium_confirmed": Keep,
	// addressing
	"ipv4_addresses": MaskIP, "ipv6_addresses": MaskIP, "has_ipv4_global": Keep,
	"apipa_only": Keep, "dhcp_lease_found": Keep, "dhcp_server": MaskIP,
	"dhcp_source": Keep,
	// routing
	"default_route_present": Keep, "gateway_ip": MaskIP, "gateway_interface": Keep,
	"default_route_count": Keep, "default_route_conflict": Keep, "route_table_size": Keep,
	// gateway_ping
	"gateway_probe_target": MaskIP, "gateway_probe_sent": Keep, "gateway_reachable": Keep,
	"gateway_loss_pct": Keep, "gateway_rtt_avg_ms": Keep, "probe_method": Keep,
	// dns
	"dns_servers": MaskIP, "dns_servers_count": Keep, "dns_resolution_ok": Keep,
	"dns_latency_ms": Keep, "dns_error": Drop,
	// neigh
	"neigh_entry_count": Keep, "neigh_incomplete_pct": Keep,
	"gateway_arp_state": Keep, "gateway_mac": MaskMAC,
	// sockets
	"sockets_listening": Keep, "sockets_established": Keep, "sockets_time_wait": Keep,
	"sockets_udp": Keep, "listening_ports": Keep,
	// net_quality
	"upstream_probe_target": Keep, "upstream_reachable": Keep,
	"upstream_loss_pct": Keep, "upstream_rtt_avg_ms": Keep, "upstream_jitter_ms": Keep,
	"gateway_q_loss_pct": Keep, "gateway_q_rtt_avg_ms": Keep, "gateway_q_jitter_ms": Keep,
	"path_mtu": Keep,
	// tcp_stats
	"tcp_out_segs": Keep, "tcp_retrans_segs": Keep, "tcp_retrans_pct": Keep,
	"tcp_resets_out": Keep, "tcp_resets_per_1k": Keep, "tcp_attempt_fails": Keep,
	"tcp_estab_resets": Keep, "tcp_listen_drops": Keep, "tcp_syn_retrans": Keep,
	// time_sync
	"time_sync_configured": Keep, "time_sync_daemon": Keep, "ntp_server_used": MaskIP,
	"ntp_offset_ms": Keep, "ntp_query_ok": Keep, "ntp_error": Drop,
	// dns_extra
	"hosts_override_count": Keep, "hosts_overrides": Drop, "browser_doh": Keep,
	"resolver_answers": Drop, "resolvers_disagree": Keep, "dns_public_name_private_ip": Keep,
	// ipv6
	"ipv6_global_present": Keep, "ipv6_default_route_present": Keep,
	"ipv6_path_ok": Keep, "ipv6_probe_target": Keep,
	// captive_portal
	"captive_probe_url": Keep, "captive_probe_status": Keep,
	"captive_portal_detected": Keep, "captive_redirect_to": Drop,
	// proxy
	"proxy_configured": Keep, "proxy_url": Drop, "proxy_reachable": Keep,
	"wpad_resolvable": Keep,
	// vpn
	"vpn_interface_count": Keep, "vpn_active": Keep, "vpn_debris_count": Keep,
	"vpn_interfaces": Keep, "vpn_default_route": Keep,
	// wifi
	"wifi_present": Keep, "wifi_interface": Keep, "wifi_link_quality": Keep,
	"wifi_signal_dbm": Keep,
	"wifi_ssid":       Drop, "wifi_bssid": MaskMAC, // an SSID is a site name (§4.3)
	"wifi_freq_mhz": Keep, "wifi_channel": Keep, "wifi_band": Keep,
	"wifi_phy_rate_mbps": Keep,
	// nic_power
	"nic_power_saving": Keep, "nic_power_iface": Keep, "nic_on_usb": Keep,
	"nic_driver": Keep, "nic_driver_version": Keep, "usb_autosuspend": Keep,
	// event_history
	"events_window_hours": Keep, "link_flaps_24h": Keep,
	"wifi_disconnects_24h": Keep, "dhcp_failures_24h": Keep,
	"events_source": Keep, "link_flap_peak_window": Keep, "link_flap_peak_count": Keep,
	// Bug #31: flaps are now attributed to an interface, so the report can say
	// WHOSE link dropped. Interface names are generic (enp7s0, wlp2s0) and
	// identify no site.
	"link_flaps_attributed": Keep, "link_flap_iface": Keep,
	"link_flaps_other_ifaces": Keep, "link_flaps_other_total": Keep,
	// ad_state
	"ad_domain_joined": Keep, "ad_realm": Drop,
	"ad_azure_joined": Keep, "ad_secure_channel_ok": Keep, "ad_is_dc": Keep,
	"ad_secure_channel_probe": Keep, "ad_secure_channel_error": Keep,
	"ad_secure_channel_verifiable": Keep,

	// Facts written by the triage PROBE layer rather than by a collector.
	// Found by `netdiag selftest` (0.9.13): unclassified defaults to Drop, so
	// nothing leaked — but the entire AD evidence set silently vanished from
	// --redact reports, which is precisely the report a support engineer
	// emails to someone else. A finding whose evidence disappears is a claim
	// the reader cannot check.
	"dns_public_resolver_only": Keep,
	"ad_srv_resolved":          Keep,
	"ad_srv_kerberos_ok":       Keep,
	"ad_srv_gc_ok":             Keep,
	"ad_srv_resolver_mismatch": Keep,
	"ad_dc_count":              Keep,
	"ad_dcs_responding":        Keep,
	"ad_dc_clock_offset_ms":    Keep,
	// …but the DC names themselves, and the per-resolver answer sets, carry
	// internal hostnames and addresses. Same treatment as ad_realm.
	"ad_dcs":             Drop,
	"ad_srv_by_resolver": Drop,
	// dns_extra v1-partial closers
	"chrome_doh_policy": Keep, "doh_connections_active": Keep, "dot_connections_active": Keep,
	"doh_connection_targets": Keep, "dot_connection_targets": Keep,
	"dnssec_validating": Keep, "dnssec_probe_name": Keep,
	// proxy v1-partial closers
	"pac_url_configured": Keep, "pac_fetched": Keep, "pac_valid": Keep,
	"tls_inspection_ca_suspected": Keep, "tls_inspection_ca_vendor": Keep,
	// addressing lease detail
	"dhcp_lease_hours_left": Keep,
	// link 802.1X + wpa_ctrl detail
	"dot1x_supplicant_present": Keep, "dot1x_ifaces": Keep,
	"dot1x_active": Keep, "dot1x_eap_state": Keep, "dot1x_pae_state": Keep,
	"dot1x_port_status": Keep, "wpa_ctrl_available": Keep,
	"wifi_key_mgmt": Keep, "wifi_noise_dbm": Keep,
	"wifi_neighbor_count": Keep, "wifi_cochannel_aps": Keep,
	"wifi_adjacent_aps": Keep, "wifi_same_ssid_bssids": Keep,
	// print_spooler — queue depths carry no site identity; the port name can
	// be a server\share or an IP, so it is dropped under --anon.
	"spooler_running": Keep, "print_queue_depth": Keep,
	"print_jobs_errored": Keep, "print_jobs_stuck_15min": Keep,
	"print_queue_readable": Keep, "default_printer_port": Drop,
	// target probes (why cant-reach/print/rdp) — the target's identity is
	// site-specific, its reachability is not.
	"target_name": Drop, "target_resolved": Keep, "target_is_ip_literal": Keep,
	"target_ips": Drop, "target_resolve_error": Drop, "target_ping_ok": Keep,
	"target_port_state": Keep, "target_port_states": Keep, "target_open_port": Keep,
	// hygiene (§12) — posture, not identity: the port list is Keep because
	// "23/Telnet is open" is the finding; nothing here names the site.
	"hygiene_risky_listeners": Keep, "hygiene_risky_listener_count": Keep,
	"hygiene_poisoning_protocols": Keep, "hygiene_poisoning_exposed": Keep,
	"hygiene_smb1_enabled": Keep, "hygiene_rdp_nla": Keep,
	// firewall
	"firewall_tool": Keep, "firewall_active": Keep, "firewall_rule_count": Keep,
	"firewall_input_policy": Keep, "firewall_blocked_listeners": Keep,
	"firewall_blocked_listener_count": Keep,
}

// Redact applies the policy in place. Unknown keys are dropped — the safe
// default for a field someone forgot to classify.
func (s *Snapshot) Redact() {
	s.Hostname = "redacted-host"
	for name, res := range s.Collectors {
		for k, v := range res.Data {
			switch RedactionPolicy[k] {
			case Keep:
				// untouched
			case MaskIP:
				res.Data[k] = maskIPValue(v)
			case MaskMAC:
				res.Data[k] = maskMAC(fmt.Sprintf("%v", v))
			default: // Drop or unclassified
				delete(res.Data, k)
			}
		}
		s.Collectors[name] = res
	}
}

func maskIPValue(v any) any {
	switch t := v.(type) {
	case string:
		return maskIP(t)
	case []string:
		out := make([]string, len(t))
		for i, s := range t {
			out[i] = maskIP(s)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, s := range t {
			out[i] = maskIPValue(s)
		}
		return out
	default:
		return "masked"
	}
}

// maskIP: private addresses identify nothing off-site and stay; public
// addresses keep only their first octet/hextet.
func maskIP(s string) string {
	ip := net.ParseIP(strings.Split(s, "/")[0])
	if ip == nil {
		return "masked"
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLoopback() {
		return s
	}
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.x.x.x", v4[0])
	}
	return strings.SplitN(ip.String(), ":", 2)[0] + ":x:x"
}

// maskMAC keeps the OUI (vendor) half.
func maskMAC(s string) string {
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return "masked"
	}
	return strings.Join(parts[:3], ":") + ":xx:xx:xx"
}
