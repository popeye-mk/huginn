package triage

import (
	"strings"
	"testing"
)

// §8 fixtures: the four canonical verdicts, each from facts the passive
// collectors actually emit.
func TestBlameVerdicts(t *testing.T) {
	cases := []struct {
		name    string
		facts   map[string]any
		want    string // substring of the verdict
		failSeg string // segment expected to fail ("" = none)
	}{
		{"machine: no link",
			map[string]any{"link_up": false},
			"this machine", "This machine"},
		{"lan: dead gateway",
			map[string]any{"link_up": true, "gateway_reachable": false},
			"inside your LAN", "Your LAN"},
		{"lan: no dhcp",
			map[string]any{"link_up": true, "apipa_only": true},
			"inside your LAN", "Your LAN"},
		{"wan: lan fine, upstream dead",
			map[string]any{"link_up": true, "gateway_reachable": true, "upstream_reachable": false},
			"ISP/WAN side", "Your ISP / WAN"},
		{"wan: upstream lossy, gateway clean",
			map[string]any{"link_up": true, "gateway_reachable": true, "gateway_loss_pct": 0,
				"upstream_reachable": true, "upstream_loss_pct": 25},
			"ISP/WAN side", "Your ISP / WAN"},
		{"destination: port refused",
			map[string]any{"link_up": true, "gateway_reachable": true, "upstream_reachable": true,
				"target_name": "fileserver", "target_resolved": true,
				"target_ping_ok": true, "target_port_state": "refused"},
			"destination itself", "The destination"},
		{"all healthy",
			map[string]any{"link_up": true, "gateway_reachable": true, "upstream_reachable": true},
			"measured segments are healthy", ""},
	}
	for _, c := range cases {
		b := Blame(c.facts, "")
		if !strings.Contains(b.Verdict, c.want) {
			t.Errorf("%s: verdict %q lacks %q", c.name, b.Verdict, c.want)
		}
		for _, s := range b.Segments {
			if s.Name == c.failSeg && s.Status != SegFail {
				t.Errorf("%s: segment %s = %s, want fail", c.name, s.Name, s.Status)
			}
			if c.failSeg == "" && s.Status == SegFail {
				t.Errorf("%s: segment %s failed unexpectedly (%s)", c.name, s.Name, s.Evidence)
			}
		}
	}
}

// Absence is never health: empty facts blame nothing and mark unknowns.
func TestBlameOnEmptyFacts(t *testing.T) {
	b := Blame(map[string]any{}, "")
	for _, s := range b.Segments {
		if s.Status == SegFail {
			t.Errorf("segment %s failed on empty facts", s.Name)
		}
		if s.Status == SegOK {
			t.Errorf("segment %s silently green on empty facts", s.Name)
		}
	}
	if !strings.Contains(b.Verdict, "nothing could be measured") {
		t.Errorf("verdict on empty facts: %q", b.Verdict)
	}
}

// A broken LAN makes the WAN unknowable, not guilty.
func TestBlameWanUnknownBehindBrokenLan(t *testing.T) {
	b := Blame(map[string]any{"link_up": true, "gateway_reachable": false,
		"upstream_reachable": false}, "")
	var wan Segment
	for _, s := range b.Segments {
		if s.Name == "Your ISP / WAN" {
			wan = s
		}
	}
	if wan.Status != SegUnknown {
		t.Errorf("WAN behind broken LAN = %s, want unknown", wan.Status)
	}
}

// The walk stops naming the first break and prunes findings to its layers.
func TestWalkFirstBreak(t *testing.T) {
	p := Profiles()["no-internet"]
	facts := map[string]any{
		"link_up": true, "apipa_only": false, "default_route_present": true,
		"gateway_arp_state": "resolved", "gateway_reachable": true,
		"upstream_reachable": false, "dns_resolution_ok": false,
	}
	out := p.Walk(facts, nil)
	// Wording changed in 0.9.20 (bug #27): a failed check leads with its
	// DETAIL, because the labels are written as assertions and read backwards
	// after a ✗. The property is unchanged — the first failing check, and only
	// the first, is named.
	if !strings.Contains(out, "First break in the walk → L3 internet past the gateway failed") {
		t.Errorf("first break not identified:\n%s", out)
	}
	if !strings.Contains(out, "nothing past the gateway answers") {
		t.Errorf("first break lost its evidence:\n%s", out)
	}
	// The LATER failure must not be the one reported.
	if strings.Contains(out, "First break in the walk → L7") {
		t.Errorf("a later break was reported as the first:\n%s", out)
	}
}

// Field-run regression (AD lab, scenarios 1 and 6): a healthy transport path
// plus a broken layer above it must NOT print "not visible from this machine".
func TestVerdictAmendedByWalkBreak(t *testing.T) {
	facts := map[string]any{"link_up": true, "gateway_reachable": true,
		"upstream_reachable": true}
	b := Blame(facts, "")
	if !strings.Contains(b.Verdict, "measured segments are healthy") {
		t.Fatalf("precondition: %q", b.Verdict)
	}
	b.NoteUnattributed("L7: DNS fit for AD — points at a public resolver")
	if strings.Contains(b.Verdict, "not visible from this machine") {
		t.Errorf("verdict still claims nothing is wrong: %q", b.Verdict)
	}
	if !strings.Contains(b.Verdict, "not the whole picture") {
		t.Errorf("verdict not amended: %q", b.Verdict)
	}
	// A real segment failure must keep its blame.
	bad := Blame(map[string]any{"link_up": true, "gateway_reachable": false}, "")
	before := bad.Verdict
	bad.NoteUnattributed("L7: something else")
	if bad.Verdict != before {
		t.Errorf("segment blame overwritten: %q", bad.Verdict)
	}
}

// Field regression (Win 11 member, clock pushed 10 min): a secure-channel
// verify that fails BECAUSE Kerberos can't authenticate across a clock skew
// must not be reported as a broken trust. The advice would be wrong and
// expensive — a rejoin instead of `w32tm /resync`.
func TestSecureChannelNotBlamedForTheClock(t *testing.T) {
	p := Profiles()["cant-login"]
	var check Check
	for _, c := range p.Checks {
		if strings.Contains(c.What, "secure channel") {
			check = c
		}
	}
	if check.Eval == nil {
		t.Fatal("secure-channel check not found")
	}
	skewed := map[string]any{
		"ad_secure_channel_ok":         false,
		"ad_secure_channel_error":      "0x5",
		"ad_secure_channel_verifiable": false,
	}
	st, detail := check.Eval(skewed)
	if st == "fail" {
		t.Errorf("blamed the trust for the clock's fault: %s", detail)
	}
	if !strings.Contains(detail, "clock") {
		t.Errorf("detail should point at the clock: %q", detail)
	}
	// With the clock fine, a real break must still be called out plainly.
	real := map[string]any{
		"ad_secure_channel_ok":         false,
		"ad_secure_channel_error":      "0x56",
		"ad_secure_channel_verifiable": true,
	}
	if st, d := check.Eval(real); st != "fail" || !strings.Contains(d, "password") {
		t.Errorf("genuine break not reported: %s %s", st, d)
	}
}

// Half of "I can't print" never leaves the machine: a stopped spooler must be
// named before the network is blamed, and an unmeasured queue must skip.
func TestCantPrintChecksTheLocalHalfFirst(t *testing.T) {
	p := Profiles()["cant-print"]
	if len(p.Checks) < 2 || p.Checks[0].What != "print spooler is running" {
		t.Fatalf("spooler check is not first: %+v", p.Checks[0].What)
	}
	if st, detail := p.Checks[0].Eval(map[string]any{"spooler_running": false}); st != "fail" ||
		!strings.Contains(detail, "STOPPED") {
		t.Errorf("stopped spooler not caught: %s %s", st, detail)
	}
	// Absence is never health: no fact = skip, not green.
	if st, _ := p.Checks[0].Eval(map[string]any{}); st != "skip" {
		t.Errorf("unmeasured spooler reported as %q, want skip", st)
	}
	if st, _ := p.Checks[1].Eval(map[string]any{}); st != "skip" {
		t.Errorf("unreadable queue reported as %q, want skip", st)
	}
	// An empty queue is a real, measured OK.
	if st, _ := p.Checks[1].Eval(map[string]any{"print_queue_depth": 0}); st != "ok" {
		t.Errorf("empty queue reported as %q, want ok", st)
	}
	if st, d := p.Checks[1].Eval(map[string]any{"print_queue_depth": 4, "print_jobs_errored": 2}); st != "fail" ||
		!strings.Contains(d, "error state") {
		t.Errorf("errored jobs not caught: %s %s", st, d)
	}
}

// cant-login without a domain skips honestly instead of inventing a DC.
func TestCantLoginNoDomain(t *testing.T) {
	p := Profiles()["cant-login"]
	facts := map[string]any{}
	if p.Prepare != nil {
		p.Prepare(facts, "")
	}
	out := p.Walk(facts, nil)
	if !strings.Contains(out, "no domain known") {
		t.Errorf("expected honest skip without a domain:\n%s", out)
	}
	if strings.Contains(out, "✗") {
		t.Errorf("cant-login failed a check with zero facts:\n%s", out)
	}
}
