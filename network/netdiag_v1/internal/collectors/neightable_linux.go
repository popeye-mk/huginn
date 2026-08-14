//go:build linux

package collectors

// NeighbourTable exports the raw IP→MAC map for the discovery tier. Kept
// separate from the neigh collector (which summarises) because discovery
// needs the entries themselves.

import (
	"os"
	"strings"
)

func NeighbourTable() map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return out
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		out[f[0]] = f[3]
	}
	return out
}

// LocalSubnets returns the CIDRs this machine has an address on — the only
// ranges a sweep should ever be offered for.
func LocalSubnets() []string {
	var out []string
	ifs, err := netInterfaces()
	if err != nil {
		return out
	}
	for _, cidr := range ifs {
		out = append(out, cidr)
	}
	return out
}
