package report

import (
	"strings"
	"testing"
	"time"

	"netdiag/internal/interpret"
	"netdiag/internal/schema"
)

// The report is the product. Everything else — collectors, rules, probes —
// exists to produce these sentences, and a wrong sentence is indistinguishable
// from a wrong measurement to the person reading it. These tests assert the
// PROPERTIES that must hold in every render, in all four formats:
//
//   1. a collector that did not run appears as not-checked, never as clean
//   2. a finding's next step is never dropped
//   3. the read-only promise is stated
//   4. nothing is silently omitted because it was inconvenient to print

func snapshot(collectors map[string]schema.CollectorResult) *schema.Snapshot {
	return &schema.Snapshot{
		SchemaVersion: schema.SchemaVersion,
		Tool:          "netdiag",
		ToolVersion:   "test",
		CollectedAt:   time.Date(2026, 7, 19, 15, 4, 5, 0, time.UTC),
		Hostname:      "testhost",
		OS:            "linux",
		Collectors:    collectors,
	}
}

func ok(data map[string]any) schema.CollectorResult {
	return schema.CollectorResult{Status: schema.StatusOK, Data: data}
}

func skipped(reason string) schema.CollectorResult {
	return schema.CollectorResult{Status: schema.StatusSkipped, Reason: reason}
}

var sampleFinding = interpret.Finding{
	Rule: interpret.Rule{
		ID: "ipv6_broken_dualstack", Layer: "L3", Severity: "warning",
		Confidence: "likely",
		Finding:    "IPv6 is configured but the IPv6 path is dead.",
		NextStep:   "Fix the v6 route/RA config, or disable IPv6 on this network.",
		ForUser:    "Your computer is trying a newer kind of connection that does not work here, waiting, then falling back — which feels like everything is slow.",
	},
	Evidence: map[string]any{"ipv6_global_present": true, "ipv6_path_ok": false},
}

// A layer nobody measured must never be rendered as clean. This is the single
// most important property in the tool: it is the difference between "we looked
// and it is fine" and "we did not look".
func TestUncheckedLayersAreNeverGreen(t *testing.T) {
	// Only L3 collectors ran; firewall (L4) was skipped for privilege.
	snap := snapshot(map[string]schema.CollectorResult{
		"routing":  ok(map[string]any{"default_route_present": true}),
		"firewall": skipped("ruleset not readable unprivileged (elevated tier §3.1)"),
	})

	out := Render(snap, nil, "embedded", "")

	if !strings.Contains(out, "L4  Transport") {
		t.Fatal("layer card missing L4")
	}
	// The L4 line must say unknown/not checked, never "clean".
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "L4  Transport") && strings.Contains(line, "clean") {
			t.Errorf("unmeasured L4 rendered as clean: %q", line)
		}
	}
	if !strings.Contains(out, "Not checked") {
		t.Error("the not-checked section is missing entirely")
	}
	if !strings.Contains(out, "ruleset not readable") {
		t.Error("the skip REASON was dropped — 'skipped' without why is not honest")
	}
}

// Every finding must carry its next step into the output. A finding without a
// remedy is trivia.
func TestFindingsKeepTheirNextStep(t *testing.T) {
	snap := snapshot(map[string]schema.CollectorResult{
		"ipv6": ok(map[string]any{"ipv6_global_present": true, "ipv6_path_ok": false}),
	})
	out := Render(snap, []interpret.Finding{sampleFinding}, "embedded", "")

	for _, want := range []string{
		"IPv6 is configured but the IPv6 path is dead",
		"next step",
		"Fix the v6 route/RA config",
		"ipv6_broken_dualstack", // the rule id, so feedback can name it
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report is missing %q", want)
		}
	}
}

// The read-only promise appears on every run: it is the reason the tool is
// safe to hand to someone else's machine.
func TestReadOnlyPromiseIsAlwaysStated(t *testing.T) {
	snap := snapshot(map[string]schema.CollectorResult{"link": ok(map[string]any{"link_up": true})})
	if !strings.Contains(Render(snap, nil, "embedded", ""), "Read-only run") {
		t.Error("terminal report dropped the read-only statement")
	}
	if !strings.Contains(RenderMarkdown(snap, nil, "embedded", "all clear"), "Read-only") {
		t.Error("markdown dropped the read-only statement")
	}
	if !strings.Contains(RenderHTML(snap, nil, "embedded", "all clear", nil), "Read-only") {
		t.Error("HTML dropped the read-only statement")
	}
}

// The blame verdict is the headline; when one is supplied it must appear
// BEFORE the layer detail, because that ordering is the product.
func TestBlameHeadlineComesFirst(t *testing.T) {
	snap := snapshot(map[string]schema.CollectorResult{"link": ok(map[string]any{"link_up": true})})
	const verdict = "  Verdict: the problem is past your gateway\n"
	out := Render(snap, nil, "embedded", verdict)

	vi := strings.Index(out, "the problem is past your gateway")
	li := strings.Index(out, "Layer report")
	if vi < 0 || li < 0 {
		t.Fatalf("verdict at %d, layer report at %d", vi, li)
	}
	if vi > li {
		t.Error("the layer detail was printed before the verdict — the headline must lead")
	}
}

// --for-user must drop the jargon entirely: no rule ids, no fact keys.
func TestForUserRenderingHasNoJargon(t *testing.T) {
	// The renderer wraps at 68 columns, so compare on collapsed whitespace:
	// the assertion is about WORDS, not line breaks.
	raw := RenderForUser([]interpret.Finding{sampleFinding})
	out := strings.Join(strings.Fields(raw), " ")
	if !strings.Contains(out, "feels like everything is slow") {
		t.Error("the plain-language template was not used")
	}
	for _, jargon := range []string{"ipv6_broken_dualstack", "ipv6_path_ok", "RA config"} {
		if strings.Contains(out, jargon) {
			t.Errorf("jargon %q leaked into the for-user rendering", jargon)
		}
	}
}

// Nothing to report is itself a claim, and it must be an honest one.
func TestCleanRunDoesNotOverclaim(t *testing.T) {
	snap := snapshot(map[string]schema.CollectorResult{
		"link":    ok(map[string]any{"link_up": true}),
		"routing": ok(map[string]any{"default_route_present": true}),
	})
	out := Render(snap, nil, "embedded", "")
	// "clean (within what v1 measures)" is the honest phrasing — it must not
	// become an unqualified "healthy".
	if strings.Contains(out, "everything is fine") || strings.Contains(out, "no problems") {
		t.Errorf("clean run over-claimed:\n%s", out)
	}
}

// HTML is handed to non-technical people and mailed around; it must escape
// hostile content and still carry the honest sections.
func TestHTMLEscapesAndKeepsHonestSections(t *testing.T) {
	snap := snapshot(map[string]schema.CollectorResult{
		"dns":      ok(map[string]any{"dns_resolution_ok": true}),
		"firewall": skipped("needs elevation"),
	})
	snap.Hostname = `<script>alert('x')</script>`

	html := RenderHTML(snap, []interpret.Finding{sampleFinding}, "embedded",
		"the problem is <this machine>", [][3]string{
			{"This machine", "fail", "clock is minutes off"},
			{"Your LAN", "ok", "gateway answers"},
		})

	if strings.Contains(html, "<script>alert") {
		t.Error("hostname was not escaped — the report is an injection vector")
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Error("expected the hostname to appear escaped")
	}
	if !strings.Contains(html, "&lt;this machine&gt;") {
		t.Error("the verdict was not escaped")
	}
	for _, want := range []string{"Not checked", "needs elevation", "PROBLEM", "clock is minutes off"} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
}

// Markdown is what gets pasted into a ticket; the verdict and the findings
// both have to survive the trip.
func TestMarkdownCarriesVerdictAndFindings(t *testing.T) {
	snap := snapshot(map[string]schema.CollectorResult{
		"ipv6": ok(map[string]any{"ipv6_path_ok": false}),
	})
	md := RenderMarkdown(snap, []interpret.Finding{sampleFinding}, "embedded",
		"the problem is this machine")

	for _, want := range []string{"the problem is this machine", "IPv6 is configured", "testhost"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
}

// A collector that errored is as unmeasured as one that was skipped — both
// must reach the not-checked section rather than vanishing.
func TestErroredAndTimedOutCollectorsAreListed(t *testing.T) {
	snap := snapshot(map[string]schema.CollectorResult{
		"link":     ok(map[string]any{"link_up": true}),
		"ad_state": {Status: schema.StatusTimeout, Reason: "collector exceeded its timeout"},
		"proxy":    {Status: schema.StatusError, Reason: "PAC fetch failed"},
	})
	out := Render(snap, nil, "embedded", "")

	for _, want := range []string{"ad_state", "timeout", "proxy", "PAC fetch failed"} {
		if !strings.Contains(out, want) {
			t.Errorf("not-checked section missing %q:\n%s", want, out)
		}
	}
}

// Bug #32 (Zorin, 0.9.22): an info note whose own text said "normally ignore
// it" put a ✗ on L1 Physical. The ✗ is a claim of a fault; info is by
// definition not one.
func TestInfoNotesDoNotMarkALayerAsFailing(t *testing.T) {
	snap := snapshot(map[string]schema.CollectorResult{
		"link": ok(map[string]any{"link_up": true}),
	})
	note := interpret.Finding{
		Rule: interpret.Rule{
			ID: "idle_iface_flapping", Layer: "L1", Severity: "info", Confidence: "likely",
			Finding:  "An interface that is NOT carrying this machine's traffic has been going up and down.",
			NextStep: "Normally ignore it.",
			ForUser:  "One of this computer's unused network sockets keeps reporting that nothing is plugged in.",
		},
	}
	out := Render(snap, []interpret.Finding{note}, "embedded", "")

	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "L1  Physical") {
			if strings.Contains(line, "✗") {
				t.Errorf("an info-only layer rendered as failing: %q", line)
			}
			if !strings.Contains(line, "no fault") {
				t.Errorf("the note-only layer does not say it is not a fault: %q", line)
			}
		}
	}

	// A WARNING at the same layer must still produce the ✗ — the fix must not
	// have softened real findings.
	warn := note
	warn.Severity = "warning"
	out = Render(snap, []interpret.Finding{warn}, "embedded", "")
	var sawFail bool
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "L1  Physical") && strings.Contains(line, "✗") {
			sawFail = true
		}
	}
	if !sawFail {
		t.Error("a warning no longer marks its layer — the fix went too far")
	}
}
