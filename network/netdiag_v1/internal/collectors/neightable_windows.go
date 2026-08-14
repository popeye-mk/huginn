//go:build windows

package collectors

// NeighbourTable exports the ARP entries IP Helper already gives us, in the
// same shape the Linux side produces, so the discovery tier is OS-agnostic.

func NeighbourTable() map[string]string {
	out := map[string]string{}
	rows, err := winArpTable()
	if err != nil {
		return out
	}
	for _, r := range rows {
		if r.mac != "" {
			out[r.ip] = r.mac
		}
	}
	return out
}

func LocalSubnets() []string {
	subnets, err := netInterfaces()
	if err != nil {
		return nil
	}
	return subnets
}
