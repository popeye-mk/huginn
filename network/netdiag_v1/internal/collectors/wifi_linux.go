//go:build linux

package collectors

import (
	"context"
	"netdiag/internal/run"
	"netdiag/internal/schema"
	"os"
)

// ------------------------------------------------------ Wi-Fi passive (L1, §4.1)

// wifiCollector reads /proc/net/wireless — link quality and signal level —
// without nl80211. SSID/BSSID/channel need generic netlink and stay on the
// v1 remaining list; what the kernel exposes here is reported, the rest is
// honestly absent (never guessed).
type wifiCollector struct{}

func (wifiCollector) Name() string      { return "wifi" }
func (wifiCollector) Privilege() string { return schema.PrivUnprivileged }

func (wifiCollector) Collect(_ context.Context) (map[string]any, error) {
	b, err := os.ReadFile("/proc/net/wireless")
	if err != nil {
		return nil, run.SkipError{ReasonText: "/proc/net/wireless not readable"}
	}
	iface, quality, signal, present := ProcNetWireless(string(b))
	if !present {
		return map[string]any{"wifi_present": false}, nil
	}
	data := map[string]any{
		"wifi_present":      true,
		"wifi_interface":    iface,
		"wifi_link_quality": quality,
		"wifi_signal_dbm":   signal,
	}
	// SSID/BSSID/channel/band/rate via wireless-extensions ioctls (see
	// wext_linux.go) — best-effort, absent facts on drivers that refuse.
	wextInfo(iface, data)
	// EAP state, better RSSI/noise, and channel occupancy from the
	// supplicant's own cache (wpactrl_linux.go) — needs root/netdev.
	wpaEnrichWifi(iface, data)
	return data, nil
}
