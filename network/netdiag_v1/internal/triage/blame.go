// Package triage implements the v1.1 releases of spec v2.3: the
// blame-partition verdict (§8) and the symptom-driven `why` layer walks (§6).
// Both are logic over facts the passive collectors already gather — no new
// privilege, no new probes beyond the target-specific connects in probe.go.
package triage

import (
	"fmt"
	"strings"
)

// Segment states. "Absence is never health": a segment whose probes were
// skipped is unknown, never silently green.
const (
	SegOK      = "ok"
	SegFail    = "fail"
	SegUnknown = "unknown"
)

// Segment is one row of the blame table.
type Segment struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	Confidence string `json:"confidence,omitempty"` // certain/likely on fail
	Evidence   string `json:"evidence"`
}

// BlameTable is the §8 four-segment partition plus the one-line verdict.
type BlameTable struct {
	Segments []Segment `json:"segments"`
	Verdict  string    `json:"verdict"`
}

// Blame builds the partition from scan facts (and target facts when a `why
// cant-reach`-family walk added them). dcLabel renames the fourth segment
// for the AD-flavoured walk (§6.4).
func Blame(facts map[string]any, dcLabel string) BlameTable {
	machine := machineSegment(facts)
	lan := lanSegment(facts)
	wan := wanSegment(facts, lan)
	segs := []Segment{machine, lan, wan}
	if _, hasTarget := facts["target_name"]; hasTarget {
		segs = append(segs, destinationSegment(facts, dcLabel))
	}
	return BlameTable{Segments: segs, Verdict: verdict(segs)}
}

func machineSegment(facts map[string]any) Segment {
	s := Segment{Name: "This machine"}
	switch {
	case facts["link_up"] == false:
		return fail(s, "certain", "no network interface is up at all")
	case str(facts["link_duplex"]) == "half":
		return fail(s, "likely", "link negotiated half-duplex (cable/port fault)")
	case num(facts["link_error_rate_pct"]) > 1:
		return fail(s, "likely", fmt.Sprintf("NIC error rate %.1f%% (cable/connector)", num(facts["link_error_rate_pct"])))
	case facts["proxy_configured"] == true && facts["proxy_reachable"] == false:
		return fail(s, "likely", "a proxy is configured here and not answering")
	case num(facts["ntp_offset_ms"]) > 120000:
		return fail(s, "likely", "system clock is minutes off (breaks auth/TLS)")
		// Deliberately NOT here: hosts-file overrides — they are an info-level
		// finding, not blame evidence; a broken LAN explains a failed DNS
		// probe far better than a stale hosts entry does.
	}
	if _, measured := facts["link_up"]; !measured {
		s.Status, s.Evidence = SegUnknown, "link state was not measured"
		return s
	}
	s.Status, s.Evidence = SegOK, "link, addressing and local config look healthy"
	return s
}

func lanSegment(facts map[string]any) Segment {
	s := Segment{Name: "Your LAN"}
	switch {
	case facts["apipa_only"] == true:
		return fail(s, "certain", "DHCP asked, no server answered (APIPA self-address)")
	case str(facts["gateway_arp_state"]) == "incomplete":
		return fail(s, "likely", "the gateway never answers ARP (dead/wrong gateway or VLAN)")
	case facts["gateway_reachable"] == false:
		return fail(s, "likely", "the default gateway does not answer")
	case num(facts["gateway_loss_pct"]) > 20:
		return fail(s, "likely", fmt.Sprintf("%.0f%% loss to the gateway itself", num(facts["gateway_loss_pct"])))
	case numOr(facts["wifi_signal_dbm"], 0) < -75:
		return fail(s, "likely", fmt.Sprintf("Wi-Fi signal %.0f dBm — weak link to the AP", num(facts["wifi_signal_dbm"])))
	}
	if facts["gateway_reachable"] == true {
		s.Status, s.Evidence = SegOK, "gateway answers with acceptable loss"
		return s
	}
	s.Status, s.Evidence = SegUnknown, "gateway path was not (fully) measured"
	return s
}

func wanSegment(facts map[string]any, lan Segment) Segment {
	s := Segment{Name: "Your ISP / WAN"}
	if lan.Status == SegFail {
		s.Status, s.Evidence = SegUnknown, "cannot judge the WAN through a broken LAN"
		return s
	}
	switch {
	case facts["gateway_reachable"] == true && facts["upstream_reachable"] == false:
		return fail(s, "likely", "LAN is fine but nothing past the gateway answers")
	case num(facts["upstream_loss_pct"]) > 10 && numOr(facts["gateway_loss_pct"], 0) <= 5:
		return fail(s, "likely", fmt.Sprintf("%.0f%% loss on the upstream path, gateway clean", num(facts["upstream_loss_pct"])))
	case num(facts["upstream_jitter_ms"]) > 30:
		return fail(s, "likely", fmt.Sprintf("upstream jitter %.0f ms — unstable ISP path", num(facts["upstream_jitter_ms"])))
	}
	if facts["upstream_reachable"] == true {
		s.Status, s.Evidence = SegOK, "past the gateway, the path to the internet is clean"
		return s
	}
	s.Status, s.Evidence = SegUnknown, "upstream path was not measured"
	return s
}

func destinationSegment(facts map[string]any, dcLabel string) Segment {
	name := "The destination"
	if dcLabel != "" {
		name = dcLabel
	}
	s := Segment{Name: name}
	target := str(facts["target_name"])
	switch {
	case facts["target_resolved"] == false:
		return fail(s, "likely", fmt.Sprintf("%s does not resolve in DNS", target))
	case str(facts["target_port_state"]) == "refused":
		return fail(s, "certain", fmt.Sprintf("%s answers but refuses the service port — the service is down or firewalled there", target))
	case str(facts["target_port_state"]) == "filtered" && facts["target_ping_ok"] == true:
		return fail(s, "likely", fmt.Sprintf("%s is alive but the service port is silently dropped", target))
	case facts["target_ping_ok"] == false && str(facts["target_port_state"]) == "filtered":
		return fail(s, "likely", fmt.Sprintf("no answer from %s at all (host down, or filtered end to end)", target))
	}
	if str(facts["target_port_state"]) == "open" {
		s.Status, s.Evidence = SegOK, fmt.Sprintf("%s is reachable and the service port answers", target)
		return s
	}
	s.Status, s.Evidence = SegUnknown, "destination was not (fully) probed"
	return s
}

func fail(s Segment, conf, why string) Segment {
	s.Status, s.Confidence, s.Evidence = SegFail, conf, why
	return s
}

// verdict: the one most-repeated sentence in network support (§8) — first
// failing segment in closest-first order gets the blame.
func verdict(segs []Segment) string {
	var failing, unknown []Segment
	for _, s := range segs {
		switch s.Status {
		case SegFail:
			failing = append(failing, s)
		case SegUnknown:
			unknown = append(unknown, s)
		}
	}
	switch {
	case len(failing) > 0:
		v := fmt.Sprintf("the problem is %s — %s.", lc(failing[0].Name), failing[0].Evidence)
		if len(failing) > 1 {
			var rest []string
			for _, f := range failing[1:] {
				rest = append(rest, lc(f.Name))
			}
			v += fmt.Sprintf(" (%s also show trouble — likely downstream of the same cause.)", strings.Join(rest, ", "))
		}
		return v
	case len(unknown) == len(segs):
		return "nothing could be measured — no blame assignable from this run."
	case len(unknown) > 0:
		var u []string
		for _, s := range unknown {
			u = append(u, lc(s.Name))
		}
		return fmt.Sprintf("every measured segment looks healthy; %s could not be judged (not silently green).", strings.Join(u, ", "))
	default:
		return fmt.Sprintf("all %d measured segments are healthy — whatever the user saw is not visible from this machine right now.", len(segs))
	}
}

// NoteUnattributed corrects the verdict when the transport path is healthy but
// something above it is certainly broken (a walk break, or a critical finding
// on a plain scan). Without this the headline claims "whatever the user saw is
// not visible from this machine" while a critical finding sits three lines
// below it — the contradiction two AD field runs produced (public-resolver DNS
// and a deleted _gc SRV record: every segment green, login impossible).
// Segments themselves are left untouched: they measured what they measured.
func (b *BlameTable) NoteUnattributed(detail string) {
	if detail == "" {
		return
	}
	for _, s := range b.Segments {
		if s.Status == SegFail {
			return // a segment already owns the blame; don't overwrite it
		}
	}
	// Wording matters as much as the trigger here. Widening this to warnings
	// (bug #25) immediately exposed that the old sentence assumed the finding
	// sat ABOVE the transport path — true for a bad resolver, false for 127
	// link flaps at L1, which are not above anything. They are invisible for a
	// different reason: they already happened.
	//
	// So the claim is now the narrow one that is always true — the segments
	// were healthy AT THE MOMENT OF MEASUREMENT — and the finding is named
	// without asserting where it sits.
	b.Verdict = fmt.Sprintf("all measured segments are healthy right now, but that is "+
		"not the whole picture — %s", firstSentence(detail))
}

// firstSentence keeps a headline to a headline. Finding text is written to be
// complete, which is right in the findings list and wrong in a one-line
// verdict: the full text of the link-flap rule ran to three clauses and a
// stray double full stop.
func firstSentence(s string) string {
	s = strings.TrimSpace(s)
	for i, r := range s {
		if r == '.' && i > 0 && i+1 < len(s) && (s[i+1] == ' ' || s[i+1] == '\n') {
			return strings.TrimSpace(s[:i+1])
		}
	}
	if !strings.HasSuffix(s, ".") && !strings.HasSuffix(s, "!") && !strings.HasSuffix(s, "?") {
		s += "."
	}
	return s
}

func lc(s string) string {
	switch s {
	case "This machine":
		return "this machine"
	case "Your LAN":
		return "inside your LAN"
	case "Your ISP / WAN":
		return "past your gateway, on the ISP/WAN side"
	case "The destination":
		return "the destination itself"
	}
	return strings.ToLower(s)
}

// Render prints the §8 table for the terminal report.
func (b BlameTable) Render() string {
	var sb strings.Builder
	sb.WriteString("  Blame partition\n  " + strings.Repeat("─", 62) + "\n")
	for _, s := range b.Segments {
		mark := "?"
		switch s.Status {
		case SegOK:
			mark = "✓"
		case SegFail:
			mark = "✗"
		}
		conf := ""
		if s.Confidence != "" {
			conf = " [" + s.Confidence + "]"
		}
		fmt.Fprintf(&sb, "  %-16s %s  %s%s\n", s.Name, mark, s.Evidence, conf)
	}
	sb.WriteString("\n  Verdict: " + b.Verdict + "\n")
	return sb.String()
}

// --- tiny fact accessors (facts arrive as bool/string/int/float64) ---

func str(v any) string {
	s, _ := v.(string)
	return s
}

// intOK distinguishes "measured zero" from "never measured" — the difference
// between an empty print queue and a queue nobody could read.
func intOK(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	}
	return 0, false
}

func num(v any) float64 {
	switch n := v.(type) {
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case float64:
		return n
	}
	return 0
}

// numOr returns fallback when the fact is absent (so "< -75" style checks
// cannot fire on unmeasured data).
func numOr(v any, fallback float64) float64 {
	switch n := v.(type) {
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case float64:
		return n
	}
	return fallback
}
