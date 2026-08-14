package main

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"netdiag/internal/interpret"

	"netdiag/internal/loadtest"
)

// The verb layer was 0% covered, and it is where the "-url was silently
// ignored" bug lived: a flag the user typed, quietly overridden, with the
// report showing a different server than the one asked for. These tests cover
// the parts of that layer that can be asserted without a network: the menu
// catalogue, the exit-code contract, and the text helpers.

// Every menu entry must be runnable and self-explanatory. A menu row with no
// runner is a dead end; a row with no label is a mystery number.
func TestMenuCatalogueIsComplete(t *testing.T) {
	items := menuItems()
	if len(items) < 10 {
		t.Fatalf("menu has only %d entries — the guided path is the main interface", len(items))
	}
	for i, it := range items {
		if it.run == nil {
			t.Errorf("entry %d (%q) has no runner", i+1, it.label)
		}
		if strings.TrimSpace(it.label) == "" {
			t.Errorf("entry %d has no label", i+1)
		}
		if it.hint == "" {
			t.Errorf("entry %d (%q) has no hint — the label alone rarely explains the check", i+1, it.label)
		}
		// Anything that asks a question must say how to get out of it. The
		// "0 = back" affordance was added because the menu trapped people.
		if it.needs != "" && !strings.Contains(it.needs, "?") {
			t.Errorf("entry %d (%q) prompts with %q, which is not a question", i+1, it.label, it.needs)
		}
	}
}

// The menu is meant to be readable by someone who does not know the jargon;
// the LABELS are symptoms, not verbs. (Hints may be technical — that is where
// the detail belongs.)
func TestMenuLabelsAreInUserLanguage(t *testing.T) {
	jargon := []string{"SRV", "ICMP", "MTU", "collector", "L3", "L7", "verb"}
	for _, it := range menuItems() {
		for _, j := range jargon {
			if strings.Contains(it.label, j) {
				t.Errorf("label %q contains jargon %q — labels are what the user says, not what we measure", it.label, j)
			}
		}
	}
}

// The speed verb's exit code is a contract: scripts gate on it, so a bad
// bufferbloat grade must be non-zero and a good one zero.
func TestExitForGradeContract(t *testing.T) {
	cases := map[loadtest.Grade]int{
		loadtest.GradeA: 0,
		loadtest.GradeB: 0,
		loadtest.GradeC: 0, // noticeable, but not a failure to gate on
		loadtest.GradeD: 1,
		loadtest.GradeF: 1,
	}
	for grade, want := range cases {
		if got := exitForGrade(grade); got != want {
			t.Errorf("grade %s exits %d, want %d", grade, got, want)
		}
	}
}

// wrap keeps the verdict readable on a narrow VM console. It must never lose
// or duplicate a word — the verdict is the sentence people paste into tickets.
func TestWrapPreservesEveryWord(t *testing.T) {
	const verdict = "Bufferbloat: severe (6 ms to 340 ms under load, grade F). " +
		"Any upload makes calls unusable even though the speed test looks fine. " +
		"Fix: enable SQM/fq_codel on the router."

	wrapped := wrap(verdict, 40, "  ")
	if strings.Join(strings.Fields(wrapped), " ") != strings.Join(strings.Fields(verdict), " ") {
		t.Errorf("wrap changed the words:\n%s", wrapped)
	}
	for _, line := range strings.Split(wrapped, "\n") {
		// Allow one over-long line only when a single word exceeds the width.
		trimmed := strings.TrimSpace(line)
		if len(trimmed) > 40 && len(strings.Fields(trimmed)) > 1 {
			t.Errorf("line exceeds the width with room to break: %q", trimmed)
		}
	}
}

func TestF64AcceptsBothNumberShapes(t *testing.T) {
	// Facts arrive as int from collectors and float64 after a JSON round-trip;
	// a baseline loaded from disk must compare against a live scan.
	if got := f64(42); got != 42 {
		t.Errorf("int fact = %v", got)
	}
	if got := f64(42.5); got != 42.5 {
		t.Errorf("float fact = %v", got)
	}
	if got := f64("not a number"); got != 0 {
		t.Errorf("string fact should be 0, got %v", got)
	}
	if got := f64(nil); got != 0 {
		t.Errorf("absent fact should be 0, got %v", got)
	}
}

func TestDimIsSafeOnEmptyHints(t *testing.T) {
	if got := dim(""); got != "" {
		t.Errorf("empty hint produced %q — an empty pair of brackets is noise", got)
	}
	if got := dim("the full passive scan"); got != "(the full passive scan)" {
		t.Errorf("dim = %q", got)
	}
}

// Field bug (Zorin, 0.9.6): `-url <hetzner>` parsed, was stored, and the
// fallback list still won the race — so the report named OVH while the user
// had explicitly asked for Hetzner, and then the OVH throttling was very
// nearly blamed on the ISP. A typed flag must be an instruction.
func TestExplicitURLDisablesTheFallbackRace(t *testing.T) {
	const want = "https://speed.hetzner.de/100MB.bin"
	opts, err := speedOptionsFrom([]string{"-url", want})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if opts.cfg.DownloadURL != want {
		t.Errorf("DownloadURL = %q, want %q", opts.cfg.DownloadURL, want)
	}
	if len(opts.cfg.Fallbacks) != 0 {
		t.Errorf("fallbacks still active (%d) — the tool can silently test a "+
			"different server than the one asked for: %v",
			len(opts.cfg.Fallbacks), opts.cfg.Fallbacks)
	}
}

// Without -url the fallback list must survive: one hard-coded server is a
// single point of failure, and the 403 bug proved they do fail.
func TestDefaultSpeedRunKeepsItsFallbacks(t *testing.T) {
	opts, err := speedOptionsFrom(nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(opts.cfg.Fallbacks) < 2 {
		t.Errorf("only %d fallback endpoints — one bad server would kill the feature", len(opts.cfg.Fallbacks))
	}
	if opts.yes {
		t.Error("consent defaulted to yes — the one verb that spends data must ask")
	}
}

// The data ceiling and the consent prompt are the safety contract of the only
// non-passive verb. Flags must move them in the direction the user typed.
func TestSpeedFlagsReachTheConfig(t *testing.T) {
	opts, err := speedOptionsFrom([]string{
		"-seconds", "3", "-max-mb", "20", "-contracted", "500",
		"-streams", "8", "-latency-host", "9.9.9.9", "-yes",
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if opts.cfg.LoadWindow != 3*time.Second {
		t.Errorf("LoadWindow = %v", opts.cfg.LoadWindow)
	}
	if opts.cfg.MaxBytes != 20<<20 {
		t.Errorf("MaxBytes = %d, want %d — a wrong ceiling spends the user's data plan", opts.cfg.MaxBytes, 20<<20)
	}
	if opts.cfg.ContractDown != 500 {
		t.Errorf("ContractDown = %v", opts.cfg.ContractDown)
	}
	if opts.cfg.Streams != 8 {
		t.Errorf("Streams = %d", opts.cfg.Streams)
	}
	if opts.cfg.LatencyHost != "9.9.9.9" {
		t.Errorf("LatencyHost = %q", opts.cfg.LatencyHost)
	}
	if !opts.yes {
		t.Error("-yes did not reach the consent gate")
	}
}

// A malformed flag must fail loudly, not fall through to a default run that
// spends data the user did not authorise with the settings they typed.
func TestBadSpeedFlagIsRejected(t *testing.T) {
	if _, err := speedOptionsFrom([]string{"-seconds", "not-a-number"}); err == nil {
		t.Error("garbage flag value parsed without error")
	}
	if got := speedCmd([]string{"-nonexistent-flag"}); got == 0 {
		t.Errorf("unknown flag exited %d — a rejected run must not look successful", got)
	}
}

// `why slow` measures an idle link, so it structurally cannot see bufferbloat.
// The offer to run the load test exists to say that out loud — but only when
// the passive walk found nothing, and never by spending the user's data
// without asking.
func TestLoadTestIsOfferedOnlyWhenThePassiveWalkFoundNothing(t *testing.T) {
	quiet := capture(t, func() { offerLoadTest(map[string]any{}, nil) })
	if !strings.Contains(quiet, "netdiag speed") {
		t.Errorf("a clean `why slow` did not mention the one test that could still explain it:\n%s", quiet)
	}
	if !strings.Contains(quiet, "uses data") {
		t.Error("the offer did not state its cost — the consent promise starts here")
	}
	if !strings.Contains(quiet, "IDLE") {
		t.Error("the offer did not say WHY the checks above could have missed the fault")
	}

	// A walk that already explains the slowness must not be buried under a
	// pitch for a data-spending test.
	loud := capture(t, func() {
		offerLoadTest(map[string]any{}, []interpret.Finding{{
			Rule: interpret.Rule{ID: "wifi_weak_signal", Severity: "warning"},
		}})
	})
	if loud != "" {
		t.Errorf("offered a load test on top of an existing finding:\n%s", loud)
	}
}

// On Wi-Fi the radio is the other usual answer, and pointing only at the load
// test would send someone to buy a router for a signal problem.
func TestWirelessSlowAlsoPointsAtTheRadio(t *testing.T) {
	out := capture(t, func() {
		offerLoadTest(map[string]any{"link_primary_is_wireless": true}, nil)
	})
	if !strings.Contains(out, "why wifi") {
		t.Errorf("a slow Wi-Fi machine was not pointed at the Wi-Fi check:\n%s", out)
	}
}

// capture redirects stdout for the duration of fn.
func capture(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = old

	var sb strings.Builder
	if _, err := io.Copy(&sb, r); err != nil {
		t.Fatal(err)
	}
	return sb.String()
}

// The first three lines answer "is something wrong, and must I read the rest?"
// They must never over-claim, and never say "(s)".
func TestHeadlineIsHonestAndReadsLikeEnglish(t *testing.T) {
	crit := interpret.Finding{Rule: interpret.Rule{ID: "a", Severity: "critical"}}
	warn := interpret.Finding{Rule: interpret.Rule{ID: "b", Severity: "warning"}}

	cases := []struct {
		name     string
		findings []interpret.Finding
		want     string
	}{
		{"one critical", []interpret.Finding{crit}, "1 thing is broken here."},
		{"two criticals", []interpret.Finding{crit, crit}, "2 things are broken here"},
		{"one warning", []interpret.Finding{warn}, "Nothing is broken, but one thing is worth a look."},
		{"mixed", []interpret.Finding{crit, warn}, "and one more is worth a look"},
	}
	for _, tc := range cases {
		got := headline(tc.findings, "")
		if !strings.Contains(got, tc.want) {
			t.Errorf("%s: got %q, want it to contain %q", tc.name, strings.TrimSpace(got), tc.want)
		}
		if strings.Contains(got, "(s)") {
			t.Errorf("%s: %q reads like generated output", tc.name, strings.TrimSpace(got))
		}
	}

	// The clean case is the one that must not over-claim: the tool knows only
	// what it measured, and the not-checked list is part of what this means.
	clean := headline(nil, "")
	if !strings.Contains(clean, "Nothing failed the checks below") {
		t.Errorf("clean headline = %q", strings.TrimSpace(clean))
	}
	for _, forbidden := range []string{"all clear", "everything is fine", "no problems", "healthy"} {
		if strings.Contains(strings.ToLower(clean), forbidden) {
			t.Errorf("clean headline over-claimed with %q: %q", forbidden, strings.TrimSpace(clean))
		}
	}
}

// Typing "print" should find the printing check. Making someone count rows in
// a 20-entry list is the kind of friction that stops a tool being picked up.
func TestMenuSearchFindsEntriesByWord(t *testing.T) {
	items := menuItems()
	for _, tc := range []struct{ q, want string }{
		{"print", "print"},
		{"slow", "slow"},
		{"wi-fi", "wi-fi"},
		{"ticket", "ticket"},
	} {
		matches := matchItems(items, tc.q)
		if len(matches) == 0 {
			t.Errorf("searching %q found nothing", tc.q)
			continue
		}
		var hit bool
		for _, m := range matches {
			if strings.Contains(strings.ToLower(items[m].label+" "+items[m].hint), tc.want) {
				hit = true
			}
		}
		if !hit {
			t.Errorf("searching %q matched the wrong entries", tc.q)
		}
	}
	if got := matchItems(items, "zzzznothing"); len(got) != 0 {
		t.Errorf("nonsense search matched %d entries", len(got))
	}
}

// Every group heading must belong to an entry that exists, and the first entry
// must open a group — otherwise entries render above any heading, orphaned.
func TestMenuGroupsAreWellFormed(t *testing.T) {
	items := menuItems()
	if items[0].group == "" {
		t.Error("the first menu entry has no heading, so it renders above all of them")
	}
	seen := map[string]bool{}
	for _, it := range items {
		if it.group == "" {
			continue
		}
		if seen[it.group] {
			t.Errorf("group %q is opened twice — the list would show it in two places", it.group)
		}
		seen[it.group] = true
	}
	if len(seen) < 3 {
		t.Errorf("only %d groups — the point was to break up a long list", len(seen))
	}
}
