// Package ref is the offline reference (§6.3): a static cheat sheet bundled
// into the binary for the server room with no signal. No probing, no
// privilege, no authorization gate — honestly labelled as a lookup table.
package ref

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

var ports = map[int]string{
	20: "FTP data", 21: "FTP control", 22: "SSH/SFTP", 23: "Telnet (legacy, plaintext)",
	25: "SMTP", 53: "DNS", 67: "DHCP server", 68: "DHCP client", 80: "HTTP",
	88: "Kerberos (AD auth)", 110: "POP3", 123: "NTP", 135: "MS RPC endpoint mapper",
	137: "NetBIOS name (poisoning vector)", 139: "NetBIOS session", 143: "IMAP",
	161: "SNMP", 389: "LDAP (AD)", 443: "HTTPS", 445: "SMB (file shares, AD)",
	465: "SMTPS", 514: "Syslog", 587: "SMTP submission", 631: "IPP printing",
	636: "LDAPS", 853: "DNS over TLS", 993: "IMAPS", 995: "POP3S",
	1194: "OpenVPN", 1433: "MS SQL Server", 1701: "L2TP", 1723: "PPTP (obsolete VPN)",
	3268: "AD global catalog", 3306: "MySQL/MariaDB", 3389: "RDP",
	5060: "SIP (VoIP)", 5353: "mDNS/Bonjour", 5355: "LLMNR (poisoning vector)",
	5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP alternate/proxy", 9100: "Raw printing (JetDirect)",
}

type subnetInfo struct{ cidr, meaning string }

var subnets = []subnetInfo{
	{"10.0.0.0/8", "Private (RFC1918)"},
	{"172.16.0.0/12", "Private (RFC1918)"},
	{"192.168.0.0/16", "Private (RFC1918)"},
	{"100.64.0.0/10", "CGNAT (RFC6598) — ISP shared space; port-forwarding will not work"},
	{"169.254.0.0/16", "APIPA/link-local — self-assigned: DHCP asked, nobody answered"},
	{"127.0.0.0/8", "Loopback — never leaves the machine"},
	{"fe80::/10", "IPv6 link-local — every v6 host has one; not routable"},
	{"fc00::/7", "IPv6 unique-local — the v6 'private' range"},
	{"224.0.0.0/4", "IPv4 multicast"},
}

var errorCodes = []string{
	"ECONNREFUSED / WSAECONNREFUSED (10061) — host answered: nothing listens on that port (service down or wrong port), not a network fault",
	"ETIMEDOUT / WSAETIMEDOUT (10060) — no answer at all: host down, filtered, or routed into a black hole",
	"EHOSTUNREACH / WSAEHOSTUNREACH (10065) — routing gave up: no route or gateway could not forward",
	"ENETUNREACH — no route to that network at all: check default route",
	"ECONNRESET / WSAECONNRESET (10054) — connection torn down mid-flight: crashing service, idle-timeout middlebox, or RST injection",
	"NXDOMAIN — the name does not exist on the resolver you asked: DNS config or the name itself",
	"SERVFAIL — the resolver itself failed to answer: upstream DNS problem, not the name",
}

var layerLegend = []string{
	"L1 Physical — cable, NIC, radio: link up, speed/duplex, signal, errors",
	"L2 Data link — the local segment: ARP/switching, VLANs, MAC-level reality",
	"L3 Network — addressing & routing: DHCP, gateways, ICMP reachability, MTU",
	"L4 Transport — TCP/UDP: ports, sockets, retransmits, resets",
	"L7 Application — what users feel: DNS, HTTP, proxies, portals, auth, time",
}

// Lookup answers `netdiag ref [topic [arg]]`.
// refDisclaimer heads every lookup. Bug #33 (Zorin, 0.9.23): a user read the
// "Common ports" table and asked "are these ports open by me?" — a reasonable
// reading, because nothing on screen said otherwise. A reference that can be
// mistaken for a scan result is a wrong scan result waiting to be acted on.
const refDisclaimer = "  REFERENCE ONLY — this is a lookup table, the same on every machine.\n" +
	"  It is NOT a scan of this computer. To see this machine's own open\n" +
	"  ports, run a scan: they appear under listening ports and hygiene.\n\n"

func Lookup(args []string) string {
	return refDisclaimer + lookup(args)
}

func lookup(args []string) string {
	if len(args) == 0 {
		return full()
	}
	switch args[0] {
	case "port":
		if len(args) > 1 {
			return portLookup(args[1])
		}
		return section("Common ports", portLines())
	case "subnet":
		if len(args) > 1 {
			return subnetLookup(args[1])
		}
		return section("Special subnets", subnetLines())
	case "errors":
		return section("Common network error codes", errorCodes)
	case "layers":
		return section("OSI layer legend (as netdiag uses it)", layerLegend)
	default:
		return "unknown ref topic " + args[0] + " — try: port [N], subnet [IP|CIDR], errors, layers\n"
	}
}

func full() string {
	var b strings.Builder
	b.WriteString("netdiag ref — offline cheat sheet (static text, nothing probed)\n\n")
	b.WriteString(section("OSI layer legend (as netdiag uses it)", layerLegend))
	b.WriteString(section("Special subnets", subnetLines()))
	b.WriteString(section("Common network error codes", errorCodes))
	b.WriteString(section("Common ports", portLines()))
	return b.String()
}

func section(title string, lines []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  %s\n", title)
	for _, l := range lines {
		fmt.Fprintf(&b, "   • %s\n", l)
	}
	b.WriteString("\n")
	return b.String()
}

func portLines() []string {
	nums := make([]int, 0, len(ports))
	for p := range ports {
		nums = append(nums, p)
	}
	sort.Ints(nums)
	out := make([]string, len(nums))
	for i, p := range nums {
		out[i] = fmt.Sprintf("%-5d %s", p, ports[p])
	}
	return out
}

func subnetLines() []string {
	out := make([]string, len(subnets))
	for i, s := range subnets {
		out[i] = fmt.Sprintf("%-18s %s", s.cidr, s.meaning)
	}
	return out
}

func portLookup(arg string) string {
	var p int
	if _, err := fmt.Sscanf(arg, "%d", &p); err != nil {
		return "not a port number: " + arg + "\n"
	}
	if desc, ok := ports[p]; ok {
		return fmt.Sprintf("  port %d — %s\n", p, desc)
	}
	return fmt.Sprintf("  port %d — not in the built-in table (unregistered/ephemeral or app-specific)\n", p)
}

func subnetLookup(arg string) string {
	ip := net.ParseIP(strings.Split(arg, "/")[0])
	if ip == nil {
		return "not an IP or CIDR: " + arg + "\n"
	}
	for _, s := range subnets {
		_, cidr, _ := net.ParseCIDR(s.cidr)
		if cidr != nil && cidr.Contains(ip) {
			return fmt.Sprintf("  %s is in %s — %s\n", arg, s.cidr, s.meaning)
		}
	}
	if ip.To4() != nil || ip.IsGlobalUnicast() {
		return fmt.Sprintf("  %s — public/global address space\n", arg)
	}
	return fmt.Sprintf("  %s — no special classification matched\n", arg)
}
