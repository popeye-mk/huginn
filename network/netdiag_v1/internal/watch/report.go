package watch

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Summary renders the §9 output: a timestamped event log, the rhythm of
// anything that repeated, the measured spread of each metric, and one verdict
// sentence. Deliberately a report you read after the fact, not a dashboard.
func (w *Watcher) Summary() string {
	var b strings.Builder
	dur := w.last.Sub(w.started)
	fmt.Fprintf(&b, "  watch summary — %d samples over %s\n", w.Samples, roundDur(dur))
	b.WriteString("  " + strings.Repeat("─", 62) + "\n")
	if w.Normal.Known {
		fmt.Fprintf(&b, "  judged against this location's baseline (%s): normal loss %.0f%%, RTT %.0f ms\n\n",
			w.Normal.Source, w.Normal.LossPct, w.Normal.RTTms)
	} else {
		b.WriteString("  no baseline for this location — thresholds are absolute defaults.\n" +
			"  Run `netdiag baseline` here while things are healthy to sharpen this.\n\n")
	}

	// --- the timeline ---
	if len(w.Events) == 0 {
		b.WriteString("  No events. Nothing crossed a threshold during the run.\n")
		b.WriteString("  This is evidence, not proof: the fault did not occur in this window.\n")
		if w.Samples > 0 {
			b.WriteString("  Run again over the hours the user reports the problem.\n")
		}
	} else {
		fmt.Fprintf(&b, "  Timeline (%d events)\n", len(w.Events))
		for _, e := range w.Events {
			fmt.Fprintf(&b, "   %s  [%s] %s\n", e.At.Local().Format("15:04:05"), e.Severity, e.What)
		}
		b.WriteString("\n")
	}

	// --- periodicity: the finding a snapshot can never make ---
	var periodic []Periodicity
	for _, p := range w.Periodic() {
		if p.Regular {
			periodic = append(periodic, p)
		}
	}
	if len(periodic) > 0 {
		b.WriteString("  Rhythm\n")
		for _, p := range periodic {
			fmt.Fprintf(&b, "   %s recurred %d× on a regular ~%s cycle — periodicity is itself the clue;\n"+
				"     look for something scheduled on that interval (DHCP renewal, backup job, power saving, a timer).\n",
				p.Kind, p.Count, roundDur(p.MeanGap))
		}
		b.WriteString("\n")
	}

	// --- what was measured, and what was not ---
	b.WriteString("  Measured spread\n")
	writeSpread(&b, "gateway loss %", w.lossSeen, 0)
	writeSpread(&b, "gateway RTT ms", w.rttSeen, 1)
	writeSpread(&b, "DNS ms", w.dnsSeen, 0)
	if len(w.unmeasure) > 0 {
		b.WriteString("\n  Not measured on some ticks — NOT green:\n")
		var keys []string
		for k := range w.unmeasure {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "   • %s: unmeasured on %d of %d samples\n", k, w.unmeasure[k], w.Samples)
		}
	}

	fmt.Fprintf(&b, "\n  Verdict: %s\n", w.Verdict())
	b.WriteString("\n  Read-only run: nothing was configured; the only traffic sent was to\n" +
		"  this machine's own gateway and resolver (spec §3, passive tier).\n")
	return b.String()
}

// Verdict is the one sentence a technician can paste into the ticket.
func (w *Watcher) Verdict() string {
	if len(w.Events) == 0 {
		return "the fault did not occur during this window — absence of an event is not proof of health; " +
			"re-run across the time of day the user reports."
	}
	// The dominant story: worst severity wins, count breaks the tie. A single
	// link drop outranks twenty slow-DNS ticks, because it explains them.
	counts := map[string]int{}
	for _, e := range w.Events {
		if strings.HasSuffix(e.Kind, "_recovered") || e.Kind == "link_up" {
			continue // recoveries describe the end of a fault, not a fault
		}
		counts[e.Kind]++
	}
	first, last := w.Events[0], w.Events[len(w.Events)-1]
	dom, n := "", 0
	for k, c := range counts {
		switch {
		case dom == "",
			sev(kindSeverity(w.Events, k)) > sev(kindSeverity(w.Events, dom)),
			sev(kindSeverity(w.Events, k)) == sev(kindSeverity(w.Events, dom)) && c > n:
			dom, n = k, c
		}
	}
	if dom == "" { // only recoveries recorded — nothing to blame
		return "only recovery events were recorded; no fault was captured in this window."
	}
	story := map[string]string{
		"link_down":            "the physical link dropped during the run — this is a cable/port/power fault, not an ISP or DNS problem",
		"link_down_at_start":   "the link was down for the whole run",
		"dns_failed_at_start":  "name resolution was failing for the whole run",
		"dns_failed_link_down": "name resolution failed only while the link was down — the resolver is not the fault here",
		"wifi_roam":            "the Wi-Fi kept moving between access points — the stalls are roaming/coverage, and the fix is AP placement or roaming thresholds, not the ISP",
		"wifi_rssi_drop":       "Wi-Fi signal collapsed during the run — coverage, not capacity",
		"wifi_weak":            "Wi-Fi ran below the usable signal floor for part of the run — coverage, not capacity",
		"loss_spike":           "packet loss to the gateway spiked during the run — the fault is at or before your own router, not out on the internet",
		"rtt_spike":            "latency to the gateway rose far above this location's normal — something local is saturating or stalling the path",
		"dns_failed":           "name resolution failed while the link stayed up — the resolver is the fault, and everything looked 'connected' the whole time",
		"dns_slow":             "DNS answers went slow enough to be felt on every new connection",
		"gateway_mac_change":   "the gateway's MAC address changed mid-run — a failover or an ARP-spoofing event; explain it before dismissing it",
		"dhcp_server_change":   "a different DHCP server answered mid-run — investigate for a rogue server",
		"address_change":       "this machine's IP changed mid-run — every open connection broke at that moment",
		"gateway_change":       "the default gateway changed mid-run",
	}[dom]
	if story == "" {
		story = fmt.Sprintf("%s occurred %d× during the run", dom, n)
	}
	// A fault that was already present at the first sample and never
	// recovered is a STANDING fault. Calling that "the intermittent was
	// caught" would send the technician looking for a pattern that isn't
	// there — the thing is simply broken right now (smoke-test lesson).
	if strings.HasSuffix(dom, "_at_start") && !w.recovered(dom) {
		return story + " — it was already broken when the watch started and never recovered. " +
			"This is a standing fault, not an intermittent one: diagnose it with a plain `netdiag scan` or `why`."
	}
	return fmt.Sprintf("%s. First event %s, last %s — the intermittent WAS caught in this window.",
		story, first.At.Local().Format("15:04:05"), last.At.Local().Format("15:04:05"))
}

// recovered reports whether the standing fault named by kind ended during the
// run (link_down_at_start → link_up, dns_failed_at_start → dns_recovered).
func (w *Watcher) recovered(kind string) bool {
	want := map[string]string{
		"link_down_at_start":  "link_up",
		"dns_failed_at_start": "dns_recovered",
	}[kind]
	if want == "" {
		return false
	}
	for _, e := range w.Events {
		if e.Kind == want {
			return true
		}
	}
	return false
}

func kindSeverity(evs []Event, kind string) string {
	for _, e := range evs {
		if e.Kind == kind {
			return e.Severity
		}
	}
	return "info"
}

func sev(s string) int {
	switch s {
	case "critical":
		return 3
	case "warning":
		return 2
	}
	return 1
}

func writeSpread(b *strings.Builder, label string, xs []float64, dp int) {
	if len(xs) == 0 {
		fmt.Fprintf(b, "   %-16s unmeasured\n", label)
		return
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	med := s[len(s)/2]
	fmt.Fprintf(b, "   %-16s min %.*f  median %.*f  max %.*f  (n=%d)\n",
		label, dp, s[0], dp, med, dp, s[len(s)-1], len(s))
}

func roundDur(d time.Duration) time.Duration {
	if d >= time.Minute {
		return d.Round(time.Second)
	}
	return d.Round(100 * time.Millisecond)
}
