package collectors

// Pure parsers, deliberately free of I/O and of build tags.
//
// Every wrong answer this tool has given in the field came from turning some
// operating system's text or binary layout into a fact: French `nltest` output,
// a cached secure-channel status, hand-computed DHCP struct offsets, a shared
// IEEE OUI block. Those are all PARSING bugs, and parsing is the one thing
// that can be tested exhaustively without a network, a domain, or a laptop.
//
// So the rule for this package: collectors do I/O and call these; these do the
// interpreting and are covered by tests built from output captured on real
// machines. If a parser lives next to its syscall, it never gets tested — and
// the Windows ones could not even be COMPILED on the machine writing them.

import (
	"strconv"
	"strings"
	"time"
)

// --------------------------------------------------------------- Linux

// DefaultGatewayFromRoute extracts the IPv4 default gateway from the contents
// of /proc/net/route. The address is little-endian hex, which is exactly the
// kind of detail worth pinning in a test.
func DefaultGatewayFromRoute(routeTable string) string {
	for _, line := range strings.Split(strings.TrimSpace(routeTable), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 3 || f[1] != "00000000" { // destination 0.0.0.0 = default
			continue
		}
		gw, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil || gw == 0 {
			continue
		}
		return formatLEIPv4(uint32(gw))
	}
	return ""
}

func formatLEIPv4(v uint32) string {
	return strconv.Itoa(int(v&0xff)) + "." +
		strconv.Itoa(int((v>>8)&0xff)) + "." +
		strconv.Itoa(int((v>>16)&0xff)) + "." +
		strconv.Itoa(int((v>>24)&0xff))
}

// HexPort reads the port half of a "AABBCCDD:PPPP" /proc/net/tcp address.
func HexPort(hexAddr string) int {
	i := strings.LastIndex(hexAddr, ":")
	if i < 0 {
		return 0
	}
	p, err := strconv.ParseInt(hexAddr[i+1:], 16, 32)
	if err != nil {
		return 0
	}
	return int(p)
}

// ResolvConfServers pulls nameserver addresses out of resolv.conf text.
// Commented lines are ignored — a commented resolver is not a resolver, and
// treating one as configured would misreport a machine as healthy.
func ResolvConfServers(conf string) []string {
	var out []string
	for _, line := range strings.Split(conf, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
			continue
		}
		f := strings.Fields(t)
		if len(f) >= 2 && f[0] == "nameserver" {
			out = append(out, f[1])
		}
	}
	return out
}

// ProcNetWireless parses /proc/net/wireless. Values carry a trailing dot in
// this file ("70.", "-37.") which trips a naive number parse.
func ProcNetWireless(contents string) (iface string, quality, signal float64, present bool) {
	lines := strings.Split(strings.TrimSpace(contents), "\n")
	if len(lines) <= 2 {
		return "", 0, 0, false
	}
	f := strings.Fields(lines[2])
	if len(f) < 4 {
		return "", 0, 0, false
	}
	iface = strings.TrimSuffix(f[0], ":")
	if q, err := strconv.ParseFloat(strings.TrimSuffix(f[2], "."), 64); err == nil {
		quality = q
	}
	if s, err := strconv.ParseFloat(strings.TrimSuffix(f[3], "."), 64); err == nil {
		signal = s
	}
	return iface, quality, signal, iface != ""
}

// --------------------------------------------------------------- Windows
//
// These parse the output of Windows' own tools. They live here, WITHOUT a
// build tag, so they compile and run under test on any platform — the Windows
// parsing bugs of the field campaign were invisible precisely because this
// code could only execute on the machine that had the bug.

// SCServiceRunning reads `sc query <svc>`.
//
// Judged ENTIRELY by numbers. The obvious implementation looks for a line
// containing "STATE" — and that is wrong, because French Windows prints
// "ÉTAT", German "STATUS", and the tool would then find no state at all and
// report every service as stopped. That is a false critical finding on a
// perfectly healthy machine, and it is the same localisation trap that made
// nltest lie about the secure channel.
//
// So: every "key : value" line is examined, and the one whose value is a
// service-state number (1–7) wins. TYPE values are 16/32/272/… and cannot
// collide with that range. If no such line exists we report NOT MEASURED —
// never "stopped".
func SCServiceRunning(out string) (running, measured bool) {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		for i, tok := range f {
			if tok != ":" || i+1 >= len(f) {
				continue
			}
			n, err := strconv.Atoi(f[i+1])
			if err != nil || n < 1 || n > 7 {
				continue // TYPE, PID, flags — not a service state
			}
			return n == 4, true // 4 = SERVICE_RUNNING
		}
	}
	return false, false
}

// NetshValue pulls "Key : Value" out of netsh's aligned output. Keys are
// matched on the trimmed prefix because netsh indents inconsistently.
func NetshValue(out, key string) string {
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if !strings.HasPrefix(t, key) {
			continue
		}
		if i := strings.Index(t, ":"); i > 0 {
			return strings.TrimSpace(t[i+1:])
		}
	}
	return ""
}

// DsregcmdState reads `dsregcmd /status`.
func DsregcmdState(out string) (domainJoined, azureJoined bool, realm string) {
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "DomainJoined") && strings.Contains(t, "YES"):
			domainJoined = true
		case strings.HasPrefix(t, "AzureAdJoined") && strings.Contains(t, "YES"):
			azureJoined = true
		case strings.HasPrefix(t, "DomainName"):
			if i := strings.Index(t, ":"); i > 0 {
				realm = strings.TrimSpace(t[i+1:])
			}
		}
	}
	return domainJoined, azureJoined, realm
}

// RegValueHex returns the numeric value of a REG_DWORD from `reg query`
// output, e.g. "    EnableMulticast    REG_DWORD    0x0" → 0, true.
func RegValueHex(out, name string) (int64, bool) {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || !strings.EqualFold(f[0], name) {
			continue
		}
		raw := f[len(f)-1]
		if v, err := strconv.ParseInt(strings.TrimPrefix(strings.ToLower(raw), "0x"), 16, 64); err == nil {
			return v, true
		}
	}
	return 0, false
}

// PnPPowerSaving reads the NIC's PnPCapabilities registry value. Bits 0x18
// mean "do not allow the machine to turn this device off"; their ABSENCE is
// what enables power saving, so the sense here is easy to invert by accident.
func PnPPowerSaving(out string) (saving, measured bool) {
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "PnPCapabilities") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		v, err := strconv.ParseInt(strings.TrimPrefix(strings.ToLower(f[len(f)-1]), "0x"), 16, 64)
		if err != nil {
			continue
		}
		return v&0x18 == 0, true
	}
	return false, false
}

// PrintQueueCounts parses the "JOBS=n;ERR=n;OLD=n" line the spooler PowerShell
// snippet prints. Absent keys stay absent: an unreadable queue is not an
// empty one.
func PrintQueueCounts(out string) map[string]int {
	counts := map[string]int{}
	for _, kv := range strings.Split(strings.TrimSpace(out), ";") {
		parts := strings.SplitN(strings.TrimSpace(kv), "=", 2)
		if len(parts) != 2 {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			continue
		}
		switch parts[0] {
		case "JOBS":
			counts["depth"] = n
		case "ERR":
			counts["errored"] = n
		case "OLD":
			counts["stale"] = n
		}
	}
	return counts
}

// DHCPFromRegistry parses `reg query …\Tcpip\Parameters\Interfaces /s` into
// the per-interface lease facts. Keyed by interface GUID so the caller can
// pick the block whose address this machine actually holds.
type DHCPLease struct {
	IPAddress string
	Server    string
	ExpiryUTC int64
}

func DHCPFromRegistry(out string) map[string]DHCPLease {
	leases := map[string]DHCPLease{}
	current := ""
	cur := DHCPLease{}
	flush := func() {
		if current != "" && (cur.Server != "" || cur.IPAddress != "") {
			leases[current] = cur
		}
		cur = DHCPLease{}
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "HKEY_") {
			flush()
			current = line
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		val := f[len(f)-1]
		switch f[0] {
		case "DhcpIPAddress":
			cur.IPAddress = val
		case "DhcpServer":
			cur.Server = val
		case "LeaseTerminatesTime":
			if n, err := strconv.ParseInt(strings.TrimPrefix(strings.ToLower(val), "0x"), 16, 64); err == nil {
				cur.ExpiryUTC = n
			}
		}
	}
	flush()
	return leases
}

// WlanInterfaceNames pulls the adapter names out of `netsh wlan show
// interfaces`. It exists to give the Windows link collector a SECOND opinion
// on whether the primary interface is wireless.
//
// The first opinion is MIB_IFROW.dwType == 71, read at a struct offset that
// was reasoned from documentation rather than observed. If that offset is
// wrong it reads some unrelated DWORD — none of which equal 71 — so a wrong
// offset looks exactly like "this machine is wired" on every machine in the
// world, including a Wi-Fi laptop. That failure is invisible from inside, and
// it would make `link_negotiated_low_wired` tell a laptop user to replace a
// cable they do not own.
//
// Two independent sources cannot both be wrong in the same direction by
// accident, so when they disagree the tool declines to answer.
func WlanInterfaceNames(out string) []string {
	var names []string
	for _, line := range strings.Split(out, "\n") {
		// Judged by structure, not by the word "Name": this output is
		// localised, and the interface block always begins with a key whose
		// value is the adapter name. NetshValue already handles the spacing.
		k, v, ok := netshSplit(line)
		if !ok || v == "" {
			continue
		}
		// The adapter-name key is the first key of each interface block; every
		// other key we care about here is one we can positively exclude.
		if isWlanNameKey(k) {
			names = append(names, v)
		}
	}
	return names
}

// netshSplit splits "  Key   : value" without assuming a fixed column.
func netshSplit(line string) (key, value string, ok bool) {
	i := strings.Index(line, ":")
	if i < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:i])
	value = strings.TrimSpace(line[i+1:])
	if key == "" {
		return "", "", false
	}
	return key, value, true
}

// isWlanNameKey recognises the adapter-name row across the locales we can
// reasonably expect. A locale we do not recognise yields no names, which makes
// the medium UNCONFIRMED rather than wrong — the safe direction.
func isWlanNameKey(k string) bool {
	switch strings.ToLower(strings.TrimSpace(k)) {
	case "name", "nom", "nombre", "nome", "navn", "namn", "naam":
		return true
	}
	return false
}

// ---------------------------------------------------------------- event log

// EventCounts is what the OS's own log says happened recently, ATTRIBUTED to
// the interface it happened on.
//
// Bug #31 (Zorin, 0.9.22): the original version counted every "link is down"
// line in the journal regardless of interface. On popeye-mk's laptop that meant
// 46 flaps of enp7s0 — an unplugged Realtek ethernet port doing what unplugged
// r8169 ports do — reported as "the link went down repeatedly" on a machine
// working perfectly over Wi-Fi. The count was right. The subject of the
// sentence was wrong.
//
// This one had been cited in the project review for weeks as one of the
// genuine faults the tool found on an unplanted machine. It was a false
// positive the whole time, which is the strongest argument in this project's
// history for reading a finding's EVIDENCE rather than trusting its headline.
type EventCounts struct {
	LinkFlaps       int            // on the interface actually carrying traffic
	OtherFlaps      map[string]int // iface → flaps, for interfaces not in use
	Attributed      bool           // false when we could not tell whose flaps these are
	WifiDisconnects int
	DHCPFailures    int
	FlapHours       map[int64]int // epoch-hour → flaps on the primary, for the peak window
}

// MineEvents counts the events that matter out of journal or syslog lines.
//
// primary is the interface carrying traffic (the default route's). When it is
// empty nothing can be attributed, and the counts are reported as unattributed
// rather than silently assigned to the machine's main connection — a flap
// count with no owner is exactly the claim that produced bug #31.
func MineEvents(lines []string, primary string) EventCounts {
	c := EventCounts{FlapHours: map[int64]int{}, OtherFlaps: map[string]int{}}
	c.Attributed = primary != ""

	for _, line := range lines {
		ts, l := SplitUnixTS(line)
		low := strings.ToLower(l)
		switch {
		case strings.Contains(low, "link is down") || strings.Contains(low, "carrier lost") ||
			strings.Contains(low, "lost carrier"):
			iface := IfaceInLogLine(l)
			switch {
			case !c.Attributed:
				// No primary known: count it, but the caller must report it as
				// unattributed rather than as "your connection dropped".
				c.LinkFlaps++
			case iface == primary:
				c.LinkFlaps++
				if ts > 0 {
					c.FlapHours[ts/3600]++
				}
			case iface != "":
				c.OtherFlaps[iface]++
			default:
				// A flap line naming no interface. Cannot be attributed to the
				// primary, so it must not inflate the primary's count.
				c.OtherFlaps["(unnamed interface)"]++
			}
		case strings.Contains(low, "ctrl-event-disconnected") ||
			strings.Contains(low, "deauthenticat") || strings.Contains(low, "disassociat"):
			c.WifiDisconnects++
		case strings.Contains(low, "no dhcpoffers") || strings.Contains(low, "dhcp lease lost") ||
			strings.Contains(low, "dhcp4: request timed out"):
			c.DHCPFailures++
		}
	}
	return c
}

// IfaceInLogLine pulls the interface name out of a kernel link message.
//
// The kernel writes "<driver> <pci-id> <iface>: Link is Down" and
// systemd-networkd writes "<iface>: Lost carrier", so the name is the token
// immediately before the colon that precedes the message. Returning "" when
// there is no such token is deliberate: an unattributable line is not the
// primary interface's problem, and guessing would recreate bug #31.
func IfaceInLogLine(line string) string {
	low := strings.ToLower(line)
	for _, marker := range []string{"link is down", "carrier lost", "lost carrier"} {
		i := strings.Index(low, marker)
		if i < 0 {
			continue
		}
		head := strings.TrimSpace(line[:i])
		fields := strings.Fields(head)
		if len(fields) == 0 {
			return ""
		}
		// The name is the last token before the message, minus its colon. Do
		// NOT try to split on the last colon in the line: the kernel prefixes
		// these with a PCI id ("r8169 0000:07:00.0 enp7s0:"), and splitting
		// there yields "0000:07" — a first attempt at this returned exactly
		// that, which is why it is spelled out here.
		last := fields[len(fields)-1]
		// The name must be the token the message is attached to, i.e. it ends
		// with the colon. Some drivers repeat themselves ("igb: enp1s0 NIC
		// Link is Down"), and without this the word before the message wins —
		// "NIC" would be filed as an interface.
		if !strings.HasSuffix(last, ":") {
			return ""
		}
		name := strings.TrimSuffix(last, ":")
		if j := strings.IndexByte(name, '['); j > 0 { // systemd-networkd[700]
			name = name[:j]
		}
		if !plausibleIfaceName(name) || isLogSource(name) {
			return "" // unattributable — must not be blamed on the primary
		}
		return name
	}
	return ""
}

// isLogSource rejects the syslog program names that sit in the same position
// as an interface name ("kernel: Link is Down"). Structurally they are
// identical, so this is a list rather than a rule — and anything it does not
// recognise falls through as a NAME, which is why plausibleIfaceName runs
// first and why the caller treats "" as unattributed rather than as zero.
func isLogSource(s string) bool {
	switch strings.ToLower(s) {
	case "kernel", "systemd", "systemd-networkd", "systemd-udevd", "networkmanager",
		"wpa_supplicant", "dhclient", "dhcpcd", "avahi-daemon", "connmand", "netplan":
		return true
	}
	return false
}

func plausibleIfaceName(s string) bool {
	if len(s) > 20 {
		return false
	}
	hasLetter := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			hasLetter = true
		case r >= '0' && r <= '9', r == '-', r == '.', r == '_':
		default:
			return false
		}
	}
	return hasLetter
}

// SplitUnixTS peels the short-unix timestamp off a journal line
// ("1721312345.123456 host msg"). Syslog lines have no such prefix and come
// back with ts=0, which correctly excludes them from the peak-hour clustering
// rather than bucketing them all into 1970.
func SplitUnixTS(line string) (int64, string) {
	i := strings.IndexByte(line, ' ')
	if i <= 0 {
		return 0, line
	}
	tsPart := line[:i]
	if j := strings.IndexByte(tsPart, '.'); j > 0 {
		tsPart = tsPart[:j]
	}
	ts, err := strconv.ParseInt(tsPart, 10, 64)
	if err != nil {
		return 0, line
	}
	return ts, line[i+1:]
}

// ------------------------------------------------------------ firewall (nft)

// FirewallSummary is the shape of a host firewall, judged without needing to
// understand the whole ruleset.
type FirewallSummary struct {
	RuleCount   int
	InputPolicy string // accept / drop / reject / "" when not stated
	Measured    bool
}

// SummariseNftables reads `nft list ruleset` output. The input policy is the
// fact that matters: "42 rules" says nothing about whether traffic is allowed,
// and a default-accept firewall with many rules is not a firewall.
//
// An unreadable or unrecognised ruleset yields Measured=false, never
// "policy accept" — guessing permissive would understate the exposure, and
// guessing restrictive would blame the firewall for someone else's fault.
func SummariseNftables(out string) FirewallSummary {
	var s FirewallSummary
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "type filter hook input"); i >= 0 {
			if j := strings.Index(line, "policy "); j >= 0 {
				p := strings.TrimSpace(line[j+len("policy "):])
				p = strings.TrimSuffix(strings.TrimSpace(strings.Split(p, ";")[0]), ";")
				s.InputPolicy = strings.ToLower(p)
				s.Measured = true
			}
			continue
		}
		// Count only actual rule lines, not the table/chain scaffolding.
		if strings.HasPrefix(line, "table ") || strings.HasPrefix(line, "chain ") ||
			line == "}" || line == "{" || strings.HasSuffix(line, "{") {
			continue
		}
		s.RuleCount++
		s.Measured = true
	}
	return s
}

// SummariseIptables reads `iptables -S` output, which states the policy on its
// own -P lines.
func SummariseIptables(out string) FirewallSummary {
	var s FirewallSummary
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, "-P INPUT "):
			s.InputPolicy = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, "-P INPUT ")))
			s.Measured = true
		case strings.HasPrefix(line, "-P "):
			s.Measured = true // other chains: counted as measured, not as rules
		case strings.HasPrefix(line, "-A ") || strings.HasPrefix(line, "-N "):
			s.RuleCount++
			s.Measured = true
		}
	}
	return s
}

// -------------------------------------------------------------- DHCP leases

// LeaseServerFrom pulls the DHCP server identifier out of one lease file's
// contents. Two formats, because the three lease locations Linux uses are
// written by three different daemons: systemd-networkd's KEY=VALUE and
// dhclient's `option ... ;` statements.
//
// This is the fact that reported "255" in the field once already (that was the
// Windows path, via a wrong struct offset). Here the risk is different and
// quieter: a lease file that exists but states no server yields "", and the
// caller must treat that as NOT MEASURED rather than as "no DHCP server",
// which would read as a broken DHCP.
func LeaseServerFrom(contents string) (string, bool) {
	for _, line := range strings.Split(contents, "\n") {
		line = strings.TrimSpace(line)
		for _, key := range []string{"SERVER_ADDRESS=", "option dhcp-server-identifier "} {
			if !strings.HasPrefix(line, key) {
				continue
			}
			v := strings.Trim(strings.TrimSuffix(strings.TrimPrefix(line, key), ";"), " \"")
			if v != "" && plausibleIPv4(v) {
				return v, true
			}
		}
	}
	return "", false
}

// LeaseExpiryFrom returns the newest `expire` timestamp in a dhclient lease
// file. dhclient appends, never rewrites, so a file holds every lease this
// interface has ever had — taking the first match would report an expiry from
// months ago and claim the lease had lapsed.
func LeaseExpiryFrom(contents string) (time.Time, bool) {
	var latest time.Time
	for _, line := range strings.Split(contents, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), ";"))
		if !strings.HasPrefix(line, "expire ") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		// expire <weekday> <yyyy/mm/dd> <hh:mm:ss>, UTC per dhclient(8)
		if t, err := time.Parse("2006/01/02 15:04:05", f[2]+" "+f[3]); err == nil && t.After(latest) {
			latest = t
		}
	}
	return latest, !latest.IsZero()
}

// plausibleIPv4 rejects the values that a mis-parse produces: a bare octet, a
// truncated address, anything that is not four numbers in range. It exists
// because "255" once shipped as a DHCP server address.
func plausibleIPv4(s string) bool {
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}
