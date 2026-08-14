//go:build linux

package collectors

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"

	"netdiag/internal/schema"
)

// ---------------------------------------------- VPN state & debris (L3, §4.1)

// vpnCollector: tunnel adapters up/down, split vs. full tunnel (is the
// default route inside the tunnel?), and leftover-VPN-debris detection —
// down tunnel adapters that survived a client uninstall (§4.1 v2.3).
type vpnCollector struct{}

func (vpnCollector) Name() string      { return "vpn" }
func (vpnCollector) Privilege() string { return schema.PrivUnprivileged }

func (vpnCollector) Collect(_ context.Context) (map[string]any, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var vpnIfs []string
	active, debris := 0, 0
	for _, ifc := range ifs {
		if !isVPNIface(ifc.Name) {
			continue
		}
		state := "down"
		if ifc.Flags&net.FlagUp != 0 {
			state = "up"
			active++
		} else {
			debris++
		}
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
	// Full vs split tunnel: default route egressing a VPN-type interface.
	if b, err := os.ReadFile("/proc/net/route"); err == nil {
		full := false
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) >= 2 && f[1] == "00000000" && isVPNIface(f[0]) {
				full = true
			}
		}
		data["vpn_default_route"] = full
	}
	return data, nil
}

// isVPNIface: name heuristics plus the /sys tun marker. Namespace note:
// the name check works on stdlib-listed interfaces (ns-aware); /sys only
// ever adds evidence, never removes it.
func isVPNIface(name string) bool {
	for _, p := range []string{"tun", "tap", "wg", "ppp", "tailscale", "zt", "utun", "ipsec", "vti"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	if _, err := os.Stat(filepath.Join("/sys/class/net", name, "tun_flags")); err == nil {
		return true
	}
	if b, err := os.ReadFile(filepath.Join("/sys/class/net", name, "uevent")); err == nil &&
		strings.Contains(string(b), "DEVTYPE=wireguard") {
		return true
	}
	return false
}
