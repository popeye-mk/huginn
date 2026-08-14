//go:build linux

package collectors

// wpa_supplicant control-socket client (the wpa_ctrl protocol): one unixgram
// round-trip per query, read-only commands only (STATUS, SIGNAL_POLL,
// SCAN_RESULTS — never SCAN: we read the cache, we don't transmit).
// This closes two v1 partials at once:
//   - 802.1X/EAP auth state (key_mgmt, PAE state, EAP state) — wired or Wi-Fi,
//   - channel occupancy / roaming candidates from the supplicant's own
//     scan cache (co-channel and adjacent-channel AP counts, same-SSID BSSes)
// without an nl80211 client or monitor mode. Needs read access to
// /var/run/wpa_supplicant/<iface> (root or the netdev group) — honest
// absence otherwise.

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

var wpaCtrlDirs = []string{"/var/run/wpa_supplicant", "/run/wpa_supplicant"}

// wpaQuery sends one read-only command to the supplicant for iface.
func wpaQuery(iface, cmd string) (string, error) {
	var sock string
	for _, d := range wpaCtrlDirs {
		p := d + "/" + iface
		if _, err := os.Stat(p); err == nil {
			sock = p
			break
		}
	}
	if sock == "" {
		return "", fmt.Errorf("no control socket for %s", iface)
	}
	laddr := &net.UnixAddr{
		Name: fmt.Sprintf("%s/netdiag_wpa_%d_%d", os.TempDir(), os.Getpid(), time.Now().UnixNano()),
		Net:  "unixgram",
	}
	raddr := &net.UnixAddr{Name: sock, Net: "unixgram"}
	conn, err := net.DialUnix("unixgram", laddr, raddr)
	if err != nil {
		return "", err
	}
	defer func() {
		conn.Close()
		os.Remove(laddr.Name)
	}()
	_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	if _, err := conn.Write([]byte(cmd)); err != nil {
		return "", err
	}
	buf := make([]byte, 64*1024) // SCAN_RESULTS can be large
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

// parseKV parses "key=value" lines (STATUS, SIGNAL_POLL). Keys may contain
// spaces ("Supplicant PAE state"); split on the first '='.
func parseKV(s string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		if i := strings.IndexByte(line, '='); i > 0 {
			out[strings.TrimSpace(line[:i])] = strings.TrimSpace(line[i+1:])
		}
	}
	return out
}

// scanStats summarises the supplicant's cached scan results.
type scanStats struct {
	neighbors int // other BSSes visible
	coChannel int // on our frequency
	adjacent  int // within 25 MHz — overlapping in 2.4 GHz
	sameSSID  int // roaming candidates (our SSID, other BSSID)
}

// parseScanResults: rows are "bssid \t freq \t signal \t flags \t ssid".
func parseScanResults(s, ownBSSID, ownSSID string, ownFreq int) scanStats {
	var st scanStats
	for _, line := range strings.Split(s, "\n")[1:] { // skip header
		f := strings.Split(line, "\t")
		if len(f) < 5 {
			continue
		}
		bssid := strings.ToLower(strings.TrimSpace(f[0]))
		if bssid == "" || bssid == strings.ToLower(ownBSSID) {
			continue
		}
		st.neighbors++
		freq, _ := strconv.Atoi(strings.TrimSpace(f[1]))
		if ownFreq > 0 && freq > 0 {
			d := freq - ownFreq
			if d < 0 {
				d = -d
			}
			switch {
			case d == 0:
				st.coChannel++
			case d <= 25:
				st.adjacent++
			}
		}
		if ownSSID != "" && strings.TrimSpace(f[4]) == ownSSID {
			st.sameSSID++
		}
	}
	return st
}

// wpaEnrichWifi adds supplicant-derived facts to the wifi collector's data.
func wpaEnrichWifi(iface string, data map[string]any) {
	status, err := wpaQuery(iface, "STATUS")
	if err != nil {
		data["wpa_ctrl_available"] = false // root/netdev needed — honest absence
		return
	}
	data["wpa_ctrl_available"] = true
	kv := parseKV(status)
	if v := kv["key_mgmt"]; v != "" {
		data["wifi_key_mgmt"] = v
	}
	if v := kv["ssid"]; v != "" && data["wifi_ssid"] == nil {
		data["wifi_ssid"] = v
	}
	addDot1xFacts(kv, data)

	if sp, err := wpaQuery(iface, "SIGNAL_POLL"); err == nil {
		pkv := parseKV(sp)
		if v, err := strconv.ParseFloat(pkv["RSSI"], 64); err == nil {
			data["wifi_signal_dbm"] = v // supplicant's number beats /proc's
		}
		if v, err := strconv.ParseFloat(pkv["NOISE"], 64); err == nil && v < 0 {
			data["wifi_noise_dbm"] = v
		}
		if v, err := strconv.Atoi(pkv["LINKSPEED"]); err == nil && v > 0 {
			data["wifi_phy_rate_mbps"] = v
		}
		if v, err := strconv.Atoi(pkv["FREQUENCY"]); err == nil && v > 0 {
			data["wifi_freq_mhz"] = v
			if ch, band := chanBand(v); ch > 0 {
				data["wifi_channel"] = ch
				data["wifi_band"] = band
			}
		}
	}

	// Channel occupancy from the CACHED scan (read-only; no SCAN issued).
	if sc, err := wpaQuery(iface, "SCAN_RESULTS"); err == nil {
		ownBSSID, _ := data["wifi_bssid"].(string)
		ownSSID, _ := data["wifi_ssid"].(string)
		ownFreq := 0
		if v, ok := data["wifi_freq_mhz"].(int); ok {
			ownFreq = v
		}
		st := parseScanResults(sc, ownBSSID, ownSSID, ownFreq)
		data["wifi_neighbor_count"] = st.neighbors
		data["wifi_cochannel_aps"] = st.coChannel
		data["wifi_adjacent_aps"] = st.adjacent
		data["wifi_same_ssid_bssids"] = st.sameSSID
	}
}

// addDot1xFacts: EAP/802.1X state from a STATUS reply — applies to wired
// EAP interfaces exactly the same way.
func addDot1xFacts(kv map[string]string, data map[string]any) {
	keyMgmt := kv["key_mgmt"]
	eap := strings.Contains(keyMgmt, "EAP") || strings.Contains(keyMgmt, "IEEE8021X")
	data["dot1x_active"] = eap
	if !eap {
		return
	}
	if v := kv["Supplicant PAE state"]; v != "" {
		data["dot1x_pae_state"] = v
	}
	if v := kv["EAP state"]; v != "" {
		data["dot1x_eap_state"] = v
	}
	if v := kv["suppPortStatus"]; v != "" {
		data["dot1x_port_status"] = v
	}
}

// dot1xFromSupplicant queries the first supplicant-managed interface (wired
// or wireless) for the link collector's 802.1X block.
func dot1xFromSupplicant(ifaces []string, data map[string]any) {
	for _, iface := range ifaces {
		status, err := wpaQuery(iface, "STATUS")
		if err != nil {
			continue
		}
		addDot1xFacts(parseKV(status), data)
		return
	}
}
