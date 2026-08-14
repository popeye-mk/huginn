package main

// Live progress for the long runs. A full sweep sits at ~28 s of the 30 s
// passive budget and used to print NOTHING until it was done — which reads as
// a hung program, and makes people Ctrl-C a run that was working fine.
//
// Everything here goes to stderr, so `-json`, `-md` and `-html` output stay
// byte-for-byte pipeable, and a redirected run leaves no progress noise in
// the file.

import (
	"fmt"
	"os"
	"strings"

	"netdiag/internal/run"
)

// friendlyCollector translates collector ids into something a person can read
// while it scrolls past. Unknown names fall through unchanged.
var friendlyCollector = map[string]string{
	"link":           "network adapter",
	"addressing":     "IP address and DHCP lease",
	"routing":        "routing table",
	"dns":            "DNS resolution",
	"gateway_ping":   "router response",
	"neigh":          "ARP / neighbour table",
	"sockets":        "open connections",
	"net_quality":    "loss, latency and jitter",
	"tcp_stats":      "TCP error counters",
	"time_sync":      "clock and time sync",
	"dns_extra":      "DNS details (hosts file, DoH, DNSSEC)",
	"ipv6":           "IPv6 path",
	"captive_portal": "captive portal check",
	"proxy":          "proxy settings",
	"vpn":            "VPN adapters",
	"wifi":           "Wi-Fi radio",
	"nic_power":      "adapter power saving",
	"event_history":  "recent problems in the system log",
	"ad_state":       "domain membership",
	"firewall":       "firewall state",
	"print_spooler":  "print spooler and queue",
}

// startProgress turns the progress line on. It returns a function that clears
// it, which the caller must run before printing the report.
func startProgress() func() {
	if os.Getenv("NETDIAG_NO_PROGRESS") != "" {
		return func() {}
	}
	width := 0
	run.Progress = func(name string, idx, total int) {
		label := friendlyCollector[name]
		if label == "" {
			label = name
		}
		line := fmt.Sprintf("  checking %s … (%d of %d)", label, idx, total)
		// Pad to the previous width so a shorter line cannot leave debris.
		if pad := width - len(line); pad > 0 {
			line += strings.Repeat(" ", pad)
		}
		width = len(line)
		fmt.Fprintf(os.Stderr, "\r%s", line)
	}
	return func() {
		run.Progress = nil
		if width > 0 {
			fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", width))
		}
	}
}
