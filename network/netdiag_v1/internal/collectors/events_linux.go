//go:build linux

package collectors

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"netdiag/internal/run"
	"netdiag/internal/schema"
)

// -------------------------- event history — the retrospective collector (§4.1)

// eventsCollector mines what the OS already logged: link up/down transitions,
// Wi-Fi disconnects, DHCP failures — `watch` (§9) pointed backwards in time,
// for the cost of a log read. Primary source: journalctl (with timestamps,
// enabling the clustering the spec demos: "clustered between 14:00–15:00");
// fallback: /var/log/syslog; honest skip when neither is readable.
type eventsCollector struct{}

func (eventsCollector) Name() string      { return "event_history" }
func (eventsCollector) Privilege() string { return schema.PrivUnprivileged }

func (eventsCollector) Collect(ctx context.Context) (map[string]any, error) {
	lines, source, err := eventLines(ctx)
	if err != nil {
		return nil, err
	}
	// The interface carrying traffic — the default route's. The events
	// collector has to work this out itself because collectors do not see each
	// other's facts, and without it every flap line is unattributable.
	primary := primaryRouteIface()
	counts := MineEvents(lines, primary)
	data := map[string]any{
		"events_window_hours":   EventWindowHours,
		"events_source":         source,
		"link_flaps_24h":        counts.LinkFlaps,
		"link_flaps_attributed": counts.Attributed,
		"wifi_disconnects_24h":  counts.WifiDisconnects,
		"dhcp_failures_24h":     counts.DHCPFailures,
	}
	if primary != "" {
		data["link_flap_iface"] = primary
	}
	// Interfaces that flapped but are NOT the one in use: an unplugged ethernet
	// port logging link-down all day is normal and must not be reported as the
	// machine's connection dropping — but it is worth stating, because "my
	// cable does nothing" is a real ticket and this is the evidence for it.
	if len(counts.OtherFlaps) > 0 {
		names := make([]string, 0, len(counts.OtherFlaps))
		total := 0
		for n, c := range counts.OtherFlaps {
			names = append(names, fmt.Sprintf("%s (%d)", n, c))
			total += c
		}
		sort.Strings(names)
		data["link_flaps_other_ifaces"] = strings.Join(names, ", ")
		data["link_flaps_other_total"] = total
	}

	// Time clustering: the hour that owns the most flaps — an intermittent
	// finding with a when, not just a count.
	if peak, count := peakHour(counts.FlapHours); count > 1 {
		data["link_flap_peak_window"] = peak
		data["link_flap_peak_count"] = count
	}
	return data, nil
}

func eventLines(ctx context.Context) ([]string, string, error) {
	if _, err := exec.LookPath("journalctl"); err == nil {
		cmd := exec.CommandContext(ctx, "journalctl",
			"--since", fmt.Sprintf("-%dh", EventWindowHours),
			"--no-pager", "-q", "-o", "short-unix")
		if out, err := cmd.Output(); err == nil {
			return strings.Split(string(out), "\n"), "journalctl", nil
		}
	}
	// Fallback: syslog-style files (NetworkManager, dhclient, kernel).
	for _, p := range []string{"/var/log/syslog", "/var/log/messages"} {
		if b, err := os.ReadFile(p); err == nil {
			return strings.Split(string(b), "\n"), p + " (no timestamps window — whole file)", nil
		}
	}
	return nil, "", run.SkipError{ReasonText: "neither journalctl nor /var/log/syslog is readable at this privilege"}
}

func peakHour(hours map[int64]int) (string, int) {
	var bestHour int64
	best := 0
	for h, c := range hours {
		if c > best {
			best, bestHour = c, h
		}
	}
	if best == 0 {
		return "", 0
	}
	t := time.Unix(bestHour*3600, 0).Local()
	return fmt.Sprintf("%s–%s", t.Format("15:04"), t.Add(time.Hour).Format("15:04")), best
}

// primaryRouteIface returns the interface owning the default route — the one
// actually carrying traffic. Not "the first interface that is up": on this
// laptop that heuristic would have picked the unplugged ethernet port, which
// is how bug #31 stayed invisible.
func primaryRouteIface() string {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) >= 2 && f[1] == "00000000" {
			return f[0]
		}
	}
	return ""
}
