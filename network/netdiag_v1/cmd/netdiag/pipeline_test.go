package main

import (
	"strings"
	"testing"
	"time"

	"netdiag/internal/interpret"
	"netdiag/internal/report"
	"netdiag/internal/schema"
	"netdiag/internal/triage"
)

// End-to-end through the REAL pipeline — embedded rules, real blame logic,
// real renderer — driven by synthetic facts instead of a network. This is the
// level at which the tool's worst bugs appeared: each component was correct in
// isolation and the assembled sentence was still wrong.
//
// No collectors run here, so these are fast and deterministic and can assert
// what the user actually ends up reading.

func pipeline(t *testing.T, facts map[string]any, dcLabel string) (string, []interpret.Finding) {
	t.Helper()
	rules, _, err := interpret.LoadRules("")
	if err != nil {
		t.Fatalf("embedded KB failed to load: %v", err)
	}
	findings := interpret.Evaluate(rules, facts)
	blame := triage.Blame(facts, dcLabel)

	// Same amendment the scan path applies (widened by bug #25: a warning is
	// visible too, so it also outranks a "nothing to see here" headline).
	for _, f := range findings {
		if f.Severity == "critical" || f.Severity == "warning" {
			blame.NoteUnattributed(f.Finding)
			break
		}
	}

	snap := &schema.Snapshot{
		SchemaVersion: schema.SchemaVersion, Tool: "netdiag", ToolVersion: "test",
		CollectedAt: time.Now(), Hostname: "testhost", OS: "linux",
		Collectors: map[string]schema.CollectorResult{
			"link":    {Status: schema.StatusOK, Data: facts},
			"routing": {Status: schema.StatusOK, Data: facts},
			"dns":     {Status: schema.StatusOK, Data: facts},
		},
	}
	return report.Render(snap, findings, "embedded", blame.Render()), findings
}

// Field regression (AD lab, 0.5.4): DNS pointed at a public resolver on a
// domain machine. Every transport segment measured healthy, so the headline
// read "whatever the user saw is not visible from this machine right now" —
// directly above a CRITICAL finding saying the machine can never find its DC.
func TestCriticalFindingCannotCoexistWithAnAllClearHeadline(t *testing.T) {
	out, findings := pipeline(t, map[string]any{
		// transport is genuinely fine
		"link_up": true, "gateway_reachable": true, "upstream_reachable": true,
		// but the machine can never find its domain controller
		"dns_public_resolver_only": true, "ad_srv_resolved": false,
	}, "")

	var sawCritical bool
	for _, f := range findings {
		if f.Severity == "critical" {
			sawCritical = true
		}
	}
	if !sawCritical {
		t.Fatal("the public-resolver rule did not fire — fixture no longer matches the KB")
	}
	if strings.Contains(out, "not visible from this machine right now") {
		t.Errorf("all-clear headline printed above a critical finding:\n%s", out)
	}
	// The sentence changed in 0.9.20 (see blame.go): it no longer claims the
	// fault sits ABOVE the transport path, because for an L1 finding that is
	// false. The property is unchanged — the verdict must not read as an
	// all-clear, and must say the segments are not the whole story.
	if !strings.Contains(out, "not the whole picture") {
		t.Errorf("verdict did not qualify the healthy segments:\n%s", out)
	}
}

// The opposite must also hold: a genuinely quiet machine gets the all-clear,
// and the tool does not invent a fault to look useful.
func TestQuietMachineGetsTheAllClear(t *testing.T) {
	out, findings := pipeline(t, map[string]any{
		"link_up": true, "gateway_reachable": true, "upstream_reachable": true,
		"gateway_loss_pct": 0, "dns_resolution_ok": true,
	}, "")

	if len(findings) != 0 {
		t.Errorf("healthy facts produced findings: %+v", findings)
	}
	if !strings.Contains(out, "measured segments are healthy") {
		t.Errorf("healthy machine did not get the all-clear:\n%s", out)
	}
	// …but the all-clear is still qualified: absence of a fault now is not
	// proof of health.
	if !strings.Contains(out, "not visible from this machine right now") {
		t.Error("the all-clear lost its qualifier — it must not read as a guarantee")
	}
}

// A broken LAN makes everything beyond it UNKNOWABLE, not innocent. This is
// the property that stops the tool blaming an ISP for a dead local router.
func TestBrokenLanLeavesTheWanUnknownNotBlamed(t *testing.T) {
	out, _ := pipeline(t, map[string]any{
		"link_up": true, "gateway_reachable": false, "upstream_reachable": false,
	}, "")

	if strings.Contains(out, "the problem is past your gateway") {
		t.Errorf("blamed the ISP when the local gateway was dead:\n%s", out)
	}
	if !strings.Contains(out, "inside your LAN") {
		t.Errorf("did not blame the LAN:\n%s", out)
	}
}

// Empty facts must blame nobody. A tool that guesses from no data is worse
// than one that says it does not know.
func TestNoFactsBlamesNobody(t *testing.T) {
	out, findings := pipeline(t, map[string]any{}, "")

	if len(findings) != 0 {
		t.Errorf("rules fired on empty facts: %+v", findings)
	}
	if !strings.Contains(out, "nothing could be measured") {
		t.Errorf("empty run did not say so:\n%s", out)
	}
	for _, forbidden := range []string{"the problem is this machine", "the problem is inside your LAN"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("blame assigned with no evidence: %q", forbidden)
		}
	}
}

// The DC/domain segment only appears when a domain was actually named, so a
// home laptop's report is not cluttered with AD it does not have.
func TestDomainSegmentOnlyWhenRelevant(t *testing.T) {
	home, _ := pipeline(t, map[string]any{
		"link_up": true, "gateway_reachable": true, "upstream_reachable": true,
	}, "")
	if strings.Contains(home, "DC / domain") {
		t.Error("a non-domain machine was shown a DC segment")
	}

	// cant-login renames the 4th segment via DCLabel — the same string the
	// walk passes ("DC / domain"), not the DC's hostname.
	domain, _ := pipeline(t, map[string]any{
		"link_up": true, "gateway_reachable": true, "upstream_reachable": true,
		"target_name": "server.corp.local", "target_ping_ok": true,
		"target_port_state": "open",
	}, "DC / domain")
	if !strings.Contains(domain, "DC / domain") {
		t.Error("a domain run lost its DC segment")
	}
}
