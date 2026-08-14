package watch

import "time"

// FromFacts builds a Sample out of one tick's collector facts. Every field is
// a pointer or empty string when the fact is absent, so a collector that
// skipped or timed out produces "unmeasured", never a healthy-looking zero.
//
// The fact names are the same ones the snapshot side uses on both OSes, so
// watch inherits every platform the collectors already cover.
func FromFacts(at time.Time, f map[string]any) Sample {
	s := Sample{At: at}
	s.LinkUp = boolp(f["link_up"])
	s.IPv4 = firstString(f["ipv4_addresses"])
	s.GatewayIP = str(f["gateway_ip"])
	s.GatewayMAC = str(f["gateway_mac"])
	s.DHCPServer = str(f["dhcp_server"])
	s.DefaultRoutes = intp(f["default_route_count"])
	s.GatewayLoss = floatp(f["gateway_loss_pct"])
	s.GatewayRTT = floatp(f["gateway_rtt_avg_ms"])
	s.DNSOK = boolp(f["dns_resolution_ok"])
	s.DNSLatency = floatp(f["dns_latency_ms"])
	s.WifiBSSID = str(f["wifi_bssid"])
	s.WifiRSSI = floatp(f["wifi_signal_dbm"])
	s.WifiChannel = intp(f["wifi_channel"])
	return s
}

// SampleCollectors is the subset run on every tick: cheap, passive, and
// exactly the facts §9 names (loss, latency, RSSI/BSSID, DHCP, ARP, route).
// The heavy one-shots (event mining, firewall, proxy, AD, quality windows)
// are deliberately absent — they have nothing new to say every few seconds.
var SampleCollectors = []string{
	"link", "addressing", "routing", "neigh", "gateway_ping", "dns", "wifi",
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func firstString(v any) string {
	switch t := v.(type) {
	case []string:
		if len(t) > 0 {
			return t[0]
		}
	case []any:
		if len(t) > 0 {
			return str(t[0])
		}
	}
	return ""
}

func boolp(v any) *bool {
	if b, ok := v.(bool); ok {
		return &b
	}
	return nil
}

func intp(v any) *int {
	switch t := v.(type) {
	case int:
		return &t
	case float64:
		i := int(t)
		return &i
	}
	return nil
}

func floatp(v any) *float64 {
	switch t := v.(type) {
	case float64:
		return &t
	case int:
		f := float64(t)
		return &f
	case int64:
		f := float64(t)
		return &f
	}
	return nil
}
