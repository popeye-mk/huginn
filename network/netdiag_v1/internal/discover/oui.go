// Package discover implements §4.2/§11: who else is on this network.
//
// Two tiers, and the difference matters:
//
//	PASSIVE  — read the neighbour/ARP table this machine already has. No
//	           packets, no authorization needed, works everywhere. It only
//	           sees devices this machine has recently talked to, and it says
//	           so rather than pretending to be a full inventory.
//	ACTIVE   — a bounded ping sweep of the local subnet. This touches OTHER
//	           people's machines, so it is gated behind --authorized and a
//	           typed confirmation, per §3.
//
// Vendor identification is by OUI prefix. The table is small and honest: a
// few hundred prefixes covering the equipment that actually shows up in an
// SMB (and the consumer gear that reveals shadow IT). An unknown OUI is
// reported as unknown, never guessed.
package discover

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ouiVendors maps the first three MAC octets to a vendor. Chosen for
// diagnostic value: infrastructure (so a rogue gateway is recognisable),
// virtualization (so lab/VM hosts are obvious), and consumer brands (so a
// personal device on a corporate subnet stands out).
var ouiVendors = map[string]string{
	// --- virtualization: the ones you want to recognise instantly ---
	"52:54:00": "QEMU/KVM virtual",
	"08:00:27": "VirtualBox virtual",
	"00:05:69": "VMware virtual", "00:0c:29": "VMware virtual",
	"00:1c:14": "VMware virtual", "00:50:56": "VMware virtual",
	"00:15:5d": "Hyper-V virtual",
	"02:42:ac": "Docker container",
	// --- network infrastructure ---
	"00:1a:a0": "Dell", "00:14:22": "Dell", "b8:2a:72": "Dell",
	"00:0e:83": "Cisco", "00:1b:0d": "Cisco", "00:23:04": "Cisco",
	"00:26:99": "Cisco", "70:81:05": "Cisco", "f4:cf:e2": "Cisco",
	"00:1d:71": "Cisco", "6c:20:56": "Cisco",
	"00:15:6d": "Ubiquiti", "24:a4:3c": "Ubiquiti", "78:8a:20": "Ubiquiti",
	"74:83:c2": "Ubiquiti", "fc:ec:da": "Ubiquiti",
	"00:0f:b5": "Netgear", "20:4e:7f": "Netgear", "a0:40:a0": "Netgear",
	"00:14:bf": "Linksys", "c0:56:27": "Belkin/Linksys",
	"00:18:39": "Cisco-Linksys", "00:1e:e5": "Cisco-Linksys",
	"00:24:01": "D-Link", "1c:af:f7": "D-Link", "c8:be:19": "D-Link",
	"00:1d:7e": "Cisco", "00:22:6b": "Cisco-Linksys",
	"e8:de:27": "TP-Link", "50:c7:bf": "TP-Link", "a4:2b:b0": "TP-Link",
	"14:cc:20": "TP-Link", "b0:48:7a": "TP-Link",
	"00:17:9a": "D-Link", "00:26:5a": "D-Link",
	"00:90:4c": "Epigram/Broadcom ref",
	"00:1f:33": "Netgear", "2c:30:33": "Netgear",
	"00:04:96": "Extreme Networks", "00:e0:2b": "Extreme Networks",
	"00:1b:54": "Cisco", "00:07:7d": "Cisco",
	"9c:8e:99": "HP/Aruba", "00:0b:86": "Aruba", "24:de:c6": "Aruba",
	"00:1f:28": "HP", "00:24:81": "HP", "3c:d9:2b": "HP",
	"70:10:6f": "HP", "b4:99:ba": "HP",
	"00:11:88": "Enterasys", "00:12:f0": "Intel",
	"00:1b:21": "Intel", "00:1e:67": "Intel", "3c:97:0e": "Intel",
	"a0:36:9f": "Intel", "68:05:ca": "Intel", "8c:16:45": "Intel",
	"00:e0:4c": "Realtek", "52:54:ab": "Realtek",
	"00:1c:c0": "Intel", "00:21:6a": "Intel",
	"b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
	// --- printers and office kit ---
	"00:00:48": "Seiko Epson", "00:26:ab": "Seiko Epson", "a4:ee:57": "Seiko Epson",
	"00:00:85": "Canon", "00:1e:8f": "Canon", "88:87:17": "Canon",
	"00:80:77": "Brother", "00:1b:a9": "Brother", "30:05:5c": "Brother",
	"00:00:74": "Ricoh", "00:26:73": "Ricoh",
	"00:60:b0": "HP printer", "00:17:a4": "HP printer",
	"08:00:37": "Fuji Xerox", "00:00:aa": "Xerox",
	"00:1b:78": "HP", "00:23:7d": "HP",
	// --- consumer / shadow-IT signals on a corporate subnet ---
	"00:17:88": "Philips Hue", "ec:b5:fa": "Philips Hue",
	"18:b4:30": "Nest", "64:16:66": "Nest",
	"44:65:0d": "Amazon (Echo/Fire)", "68:37:e9": "Amazon", "fc:65:de": "Amazon",
	"a0:02:dc": "Amazon", "74:c2:46": "Amazon",
	"00:04:20": "Slim Devices/Logitech", "00:1f:5b": "Apple",
	"00:1e:c2": "Apple", "00:25:00": "Apple", "3c:07:54": "Apple",
	"7c:d1:c3": "Apple", "a4:83:e7": "Apple", "f0:18:98": "Apple",
	"dc:2b:2a": "Apple", "88:66:5a": "Apple", "ac:bc:32": "Apple",
	"00:16:cb": "Apple", "58:55:ca": "Apple",
	"00:12:fb": "Samsung", "00:15:99": "Samsung", "5c:0a:5b": "Samsung",
	"78:1f:db": "Samsung", "8c:77:12": "Samsung", "e8:50:8b": "Samsung",
	"00:24:e4": "Withings", "00:1a:11": "Google", "f4:f5:e8": "Google",
	"da:a1:19": "Google", "48:d6:d5": "Google",
	"b0:be:76": "TP-Link", "00:31:92": "Sonos", "94:9f:3e": "Sonos",
	"00:0e:58": "Sonos", "5c:aa:fd": "Sonos",
	"00:1d:0f": "TP-Link", "d8:0d:17": "TP-Link",
	"ac:84:c6": "TP-Link", "60:32:b1": "TP-Link",
	"00:11:32": "Synology", "00:c0:b7": "American Power Conversion",
}

// externalOUI is loaded once from the system's IEEE database if one is
// present. The built-in table covers the equipment that matters
// diagnostically, but it is small by design — on a real network most prefixes
// will not be in it (field run: the user's own router came back "unknown
// vendor"). Rather than hardcode guesses, we read the real registry when the
// machine has it, and stay honest when it does not.
var (
	externalOUI  map[string]string
	externalDate string // when the registry snapshot was published
	externalOnce sync.Once
)

// ouiDatabaseDirs hold the IEEE registry files. THREE files matter, not one:
// modern allocations are often 28-bit (MA-M, mam.txt) or 36-bit (MA-S,
// oui36.txt) blocks rather than classic 24-bit OUIs. The field run found a
// router whose prefix was in none of oui.txt — because it was a smaller
// block — and the tool reported "unknown vendor" on the user's own gateway.
var ouiDatabaseDirs = []string{
	"/usr/share/ieee-data",
	"/var/lib/ieee-data",
	"/usr/share/misc",
	"/usr/share/hwdata",
	".",
}

var ouiDatabaseFiles = []string{"oui.txt", "mam.txt", "oui36.txt"}

// loadExternalOUI parses every available registry file, keyed by the prefix
// length each entry actually declares, so lookups can match longest-first.
func loadExternalOUI() {
	externalOUI = map[string]string{}
	for _, dir := range ouiDatabaseDirs {
		found := false
		for _, name := range ouiDatabaseFiles {
			f, err := os.Open(dir + "/" + name)
			if err != nil {
				continue
			}
			parseIEEEFile(f, externalOUI)
			f.Close()
			found = true
		}
		if found && len(externalOUI) > 0 {
			// The registry AGES: a prefix registered after this snapshot is
			// legitimately absent, and the report should let the reader tell
			// "unknown because new" from "unknown because odd" (field run: a
			// 2025 router against a 2022 database).
			if b, err := os.ReadFile(dir + "/.lastupdate"); err == nil {
				if ts, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil {
					externalDate = time.Unix(ts, 0).Format("2006-01-02")
				}
			}
			return // first directory that had usable data wins
		}
	}
}

// parseIEEEFile reads an IEEE registry file. The layout matters and is NOT
// uniform across the three files:
//
//	oui.txt   "00-50-56   (hex)\t\tVMware, Inc."          — a whole 24-bit OUI
//	mam.txt   "74-1A-E0   (hex)\t\tPrivate"                 — the SHARED 24-bit OUI
//	          "900000-9FFFFF  (base 16)\t\tPrivate"         — the actual 28-bit slice
//
// So for the MA-M/MA-S files the "(hex)" line alone is not the answer: several
// organisations share one OUI and are distinguished by the (base 16) range.
// The common leading hex digits of that range extend the prefix — 900000-9FFFFF
// pins the first nibble, giving a 28-bit key.
func parseIEEEFile(r io.Reader, into map[string]string) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	lastOUI := ""
	for sc.Scan() {
		line := sc.Text()

		if i := strings.Index(line, "(hex)"); i >= 0 {
			prefix := hexOnly(line[:i])
			name := strings.TrimSpace(line[i+len("(hex)"):])
			if len(prefix) == 6 {
				lastOUI = prefix
				// Record the 24-bit entry only if nothing more specific has
				// claimed it; for shared blocks this is a weak default.
				if _, exists := into[prefix]; !exists && name != "" {
					into[prefix] = name
				}
			}
			continue
		}

		i := strings.Index(line, "(base 16)")
		if i < 0 || lastOUI == "" {
			continue
		}
		name := strings.TrimSpace(line[i+len("(base 16)"):])
		rangePart := strings.TrimSpace(line[:i])
		lo, hi, ok := strings.Cut(rangePart, "-")
		if !ok || name == "" {
			continue
		}
		// The shared part of start and end is the sub-block this org owns.
		lo, hi = hexOnly(lo), hexOnly(hi)
		common := 0
		for common < len(lo) && common < len(hi) && lo[common] == hi[common] {
			common++
		}
		if common == 0 {
			continue
		}
		into[lastOUI+lo[:common]] = name
	}
}

// hexOnly strips separators and lowercases, so "02-1A-20-F" → "0c7274f".
func hexOnly(s string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(s) {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// OUIDatabaseSize reports how many prefixes came from the system registry, so
// the report can say whether vendor lookup is thorough or best-effort.
func OUIDatabaseSize() int {
	externalOnce.Do(loadExternalOUI)
	return len(externalOUI)
}

// OUIDatabaseDate is the publication date of the registry snapshot in use,
// or "" when unknown.
func OUIDatabaseDate() string {
	externalOnce.Do(loadExternalOUI)
	return externalDate
}

// Vendor returns the vendor for a MAC, or "" when the prefix is unknown.
// Unknown is a real answer here: guessing a vendor would put a wrong name
// next to a device someone is about to investigate. The curated table wins
// over the IEEE one, because "QEMU/KVM virtual" is more useful to a
// technician than the registrant's legal name.
func Vendor(mac string) string {
	m := strings.ToLower(strings.TrimSpace(mac))
	m = strings.ReplaceAll(m, "-", ":")
	if len(m) < 8 {
		return ""
	}
	if v, ok := ouiVendors[m[:8]]; ok {
		return v
	}
	externalOnce.Do(loadExternalOUI)
	// Longest match first: a 36-bit MA-S assignment is more specific (and more
	// correct) than the 24-bit block it sits inside.
	bare := hexOnly(m)
	for _, n := range []int{9, 7, 6} {
		if len(bare) >= n {
			if v, ok := externalOUI[bare[:n]]; ok {
				return v
			}
		}
	}
	return ""
}

// LocallyAdministered reports whether a MAC has the locally-administered bit
// set — i.e. it is randomised or hand-assigned rather than burned in. Modern
// phones randomise per-SSID, so this is context for "unknown device", not an
// accusation.
func LocallyAdministered(mac string) bool {
	m := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(mac)), "-", ":")
	if len(m) < 2 {
		return false
	}
	var first int
	for _, c := range m[:2] {
		first <<= 4
		switch {
		case c >= '0' && c <= '9':
			first |= int(c - '0')
		case c >= 'a' && c <= 'f':
			first |= int(c-'a') + 10
		default:
			return false
		}
	}
	return first&0x02 != 0
}
