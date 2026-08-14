package discover

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// Device is one machine seen on the local segment.
type Device struct {
	IP        string    `json:"ip"`
	MAC       string    `json:"mac"`
	Vendor    string    `json:"vendor,omitempty"`
	Random    bool      `json:"randomised_mac,omitempty"`
	IsGateway bool      `json:"is_gateway,omitempty"`
	IsSelf    bool      `json:"is_self,omitempty"`
	Responded bool      `json:"responded,omitempty"` // active tier only
	FirstSeen time.Time `json:"first_seen,omitempty"`
}

// Inventory is the result of one discovery run.
type Inventory struct {
	Devices   []Device  `json:"devices"`
	Subnet    string    `json:"subnet,omitempty"`
	Active    bool      `json:"active_sweep"`
	SweptHost int       `json:"hosts_swept,omitempty"`
	At        time.Time `json:"at"`
}

// FromNeighbours builds the PASSIVE inventory: whatever is already in this
// machine's ARP/neighbour table. Its honest limit is important — this is not
// "everything on the network", it is "everything this machine has spoken to
// recently", and the report says exactly that.
func FromNeighbours(entries map[string]string, gatewayIP string, ownIPs []string) Inventory {
	self := map[string]bool{}
	for _, ip := range ownIPs {
		self[ip] = true
	}
	inv := Inventory{At: time.Now()}
	for ip, mac := range entries {
		if mac == "" || strings.HasPrefix(mac, "00:00:00:00:00:00") {
			continue // incomplete entry: an address we asked about and got nothing for
		}
		// Broadcast and multicast rows are protocol plumbing, not machines.
		// Field run: 255.255.255.255 / ff:ff:ff:ff:ff:ff was being listed as
		// "randomised MAC (phones do this by default)", and the mDNS/SSDP
		// multicast groups were counted as unidentified devices — three
		// wrong claims in one screen.
		if isNotADevice(ip, mac) {
			continue
		}
		inv.Devices = append(inv.Devices, Device{
			IP:        ip,
			MAC:       mac,
			Vendor:    Vendor(mac),
			Random:    LocallyAdministered(mac),
			IsGateway: ip == gatewayIP,
			IsSelf:    self[ip],
		})
	}
	sortDevices(inv.Devices)
	return inv
}

// isNotADevice filters the ARP/neighbour rows that are addressing constructs
// rather than machines: the all-ones broadcast, subnet broadcasts, and the
// IPv4 multicast range (224.0.0.0/4, whose MACs start 01:00:5e).
func isNotADevice(ip, mac string) bool {
	m := strings.ToLower(mac)
	if m == "ff:ff:ff:ff:ff:ff" || strings.HasPrefix(m, "01:00:5e") ||
		strings.HasPrefix(m, "33:33") { // IPv6 multicast
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	if parsed.IsMulticast() || parsed.Equal(net.IPv4bcast) || parsed.IsUnspecified() {
		return true
	}
	// A .255 host in a /24 is the usual subnet broadcast. Without the mask we
	// cannot be certain, so this is a heuristic — but a broadcast row paired
	// with a broadcast MAC is already caught above, and this catches the rest.
	if v4 := parsed.To4(); v4 != nil && v4[3] == 255 {
		return true
	}
	return false
}

func sortDevices(d []Device) {
	sort.Slice(d, func(i, j int) bool {
		a, b := net.ParseIP(d[i].IP), net.ParseIP(d[j].IP)
		if a != nil && b != nil {
			return lessIP(a, b)
		}
		return d[i].IP < d[j].IP
	})
}

func lessIP(a, b net.IP) bool {
	a4, b4 := a.To4(), b.To4()
	if a4 != nil && b4 != nil {
		for i := 0; i < 4; i++ {
			if a4[i] != b4[i] {
				return a4[i] < b4[i]
			}
		}
		return false
	}
	return a.String() < b.String()
}

// Render prints the inventory as the report a technician wants: who is here,
// what they are, and which entries deserve a second look.
func (inv Inventory) Render() string {
	var b strings.Builder
	if inv.Active {
		fmt.Fprintf(&b, "  Devices on %s — active sweep of %d addresses\n", inv.Subnet, inv.SweptHost)
	} else {
		b.WriteString("  Devices this machine has recently talked to (passive — from the ARP/neighbour table)\n")
	}
	b.WriteString("  " + strings.Repeat("─", 62) + "\n")
	if len(inv.Devices) == 0 {
		b.WriteString("  Nothing in the neighbour table yet. Generate some local traffic\n" +
			"  (or run the authorized sweep) and try again.\n")
		return b.String()
	}
	for _, d := range inv.Devices {
		tag := ""
		switch {
		case d.IsSelf:
			tag = "  ← this machine"
		case d.IsGateway:
			tag = "  ← the gateway"
		}
		vendor := d.Vendor
		if vendor == "" {
			vendor = "unknown vendor"
			if d.Random {
				vendor = "randomised MAC (phones do this by default)"
			}
		}
		fmt.Fprintf(&b, "  %-15s  %-17s  %s%s\n", d.IP, d.MAC, vendor, tag)
	}

	// The interpretation, not just the list.
	var notes []string
	unknown, random := 0, 0
	for _, d := range inv.Devices {
		// The gateway counts: in the field run it was the only device on the
		// list, so skipping it meant the "vendor lookup is best-effort" note
		// never appeared and the bare "unknown vendor" looked authoritative.
		if d.IsSelf {
			continue
		}
		// The locally-administered bit only tells us something when we cannot
		// already name the vendor: hypervisors set it too (52:54:00 is QEMU),
		// and calling a known KVM guest "a phone with privacy on" is wrong.
		if d.Vendor != "" {
			continue
		}
		if d.Random {
			random++
		} else {
			unknown++
		}
	}
	if unknown > 0 {
		notes = append(notes, fmt.Sprintf("%d device(s) with an unrecognised vendor prefix — "+
			"not suspicious by itself, but worth identifying on a corporate subnet", unknown))
	}
	if random > 0 {
		notes = append(notes, fmt.Sprintf("%d device(s) using a randomised MAC — typically phones/laptops "+
			"with private-address privacy on, common on guest Wi-Fi", random))
	}
	if !inv.Active {
		notes = append(notes, "PASSIVE view: this is what this machine has spoken to, NOT a full "+
			"inventory of the network — quiet devices are missing by definition")
	}
	// Say whether vendor identification was thorough or best-effort, so an
	// "unknown vendor" is read as "not in our small list" rather than as
	// "mystery device".
	if unknown > 0 {
		if n := OUIDatabaseSize(); n > 0 {
			note := fmt.Sprintf("vendor lookup used the system IEEE database (%d prefixes", n)
			if d := OUIDatabaseDate(); d != "" {
				note += ", published " + d + ") — a device registered after that date " +
					"is legitimately absent, so \"unknown\" here often just means \"newer than the list\""
			} else {
				note += ")"
			}
			notes = append(notes, note)
		} else {
			notes = append(notes, "vendor lookup used only the small built-in list — install the IEEE "+
				"database for full coverage (Debian/Ubuntu: `sudo apt install ieee-data`), or drop an "+
				"oui.txt next to the binary")
		}
	}
	if len(notes) > 0 {
		b.WriteString("\n  Reading it:\n")
		for _, n := range notes {
			fmt.Fprintf(&b, "   • %s\n", n)
		}
	}
	return b.String()
}

// NewSince returns devices present now that were absent in the baseline
// inventory — the shadow-IT / "what appeared on my network" question.
func NewSince(old, now Inventory) []Device {
	seen := map[string]bool{}
	for _, d := range old.Devices {
		seen[strings.ToLower(d.MAC)] = true
	}
	var out []Device
	for _, d := range now.Devices {
		if !seen[strings.ToLower(d.MAC)] && !d.IsSelf {
			out = append(out, d)
		}
	}
	return out
}
