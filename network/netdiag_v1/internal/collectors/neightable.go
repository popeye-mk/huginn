package collectors

// netInterfaces returns this machine's IPv4 CIDRs (e.g. "192.168.1.10/24"),
// cross-platform. Discovery uses it to offer only the subnets this machine is
// actually on — sweeping a range you are not connected to is both useless and
// exactly the kind of thing an authorization gate exists to prevent.

import (
	"net"
	"strings"
)

func netInterfaces() ([]string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagUp == 0 {
			continue
		}
		if isVirtualIface(ifc.Name) {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil || ipnet.IP.IsLinkLocalUnicast() {
				continue
			}
			out = append(out, ipnet.String())
		}
	}
	return out, nil
}

// isVirtualIface keeps container and hypervisor bridges out of the offer
// list: sweeping docker0 tells you nothing about the office network.
func isVirtualIface(name string) bool {
	l := strings.ToLower(name)
	for _, p := range []string{"docker", "veth", "virbr", "br-", "vmnet", "vboxnet", "lxc", "tun", "tap", "wg"} {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return false
}
