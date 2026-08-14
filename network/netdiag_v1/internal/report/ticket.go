package report

// The ticket export (§ roadmap item 6): the artefact a support engineer
// actually hands over.
//
// The other renderers answer "what did the tool find?". A ticket answers a
// different question — "what does the next person need in order to not repeat
// my work?" — and that makes two sections load-bearing which no other format
// has:
//
//	RULED OUT     what was measured healthy, so nobody re-tests it
//	NOT CHECKED   what nobody measured, so nobody assumes it was fine
//
// Without RULED OUT, tier 2 starts from zero. Without NOT CHECKED, a ticket
// silently implies the whole machine was examined, and the reader draws a
// conclusion the evidence does not support. That second failure is this
// project's oldest enemy wearing a new hat: absence read as health.
//
// Plain text, hard-wrapped, no markdown. It gets pasted into ticket systems
// that mangle tables and eat asterisks.

import (
	"fmt"
	"sort"
	"strings"

	"netdiag/internal/interpret"
	"netdiag/internal/schema"
)

// Ticket is everything the export needs. Segment is mirrored as a plain
// triple so this package keeps its one-way dependency on triage (report is
// imported by triage's callers, never the other way).
type Ticket struct {
	Snapshot   *schema.Snapshot
	Findings   []interpret.Finding
	Symptom    string      // "slow", "cant-login", … empty for a plain scan
	Target     string      // host the user named, if any
	Verdict    string      // the blame headline
	Segments   [][3]string // name, status (ok/fail/unknown), evidence
	FirstBreak string      // the walk's first failing check, when there was one
	KBSource   string
}

const ticketWidth = 76

// RenderTicket produces the paste-ready summary.
func RenderTicket(t Ticket) string {
	var b strings.Builder

	// Rune count, not byte count: the section titles contain em dashes, and a
	// byte-length underline runs two characters past the text.
	sec := func(title string) {
		fmt.Fprintf(&b, "\n%s\n%s\n", title, strings.Repeat("-", len([]rune(title))))
	}
	line := func(prefix, s string) { b.WriteString(hang(prefix, s, ticketWidth)) }

	// ---- header -----------------------------------------------------------
	when := t.Snapshot.CollectedAt.Format("2006-01-02 15:04 MST")
	fmt.Fprintf(&b, "NETDIAG TICKET  %s\n", when)
	fmt.Fprintf(&b, "%s\n", strings.Repeat("=", ticketWidth))
	fmt.Fprintf(&b, "host     : %s (%s)\n", t.Snapshot.Hostname, t.Snapshot.OS)
	fmt.Fprintf(&b, "tool     : %s %s, rules: %s\n", t.Snapshot.Tool, t.Snapshot.ToolVersion, t.KBSource)
	if t.Symptom != "" {
		reported := t.Symptom
		if t.Target != "" {
			reported += " — " + t.Target
		}
		fmt.Fprintf(&b, "reported : %s\n", reported)
	}

	// ---- verdict ----------------------------------------------------------
	sec("VERDICT")
	if strings.TrimSpace(t.Verdict) == "" {
		line("  ", "No verdict — see NOT CHECKED below before drawing one.")
	} else {
		line("  ", strings.TrimSpace(t.Verdict))
	}
	if t.FirstBreak != "" {
		line("  ", "First break: "+t.FirstBreak)
	}

	// ---- findings ---------------------------------------------------------
	if len(t.Findings) > 0 {
		sec("WHAT WAS FOUND")
		for i, f := range t.Findings {
			fmt.Fprintf(&b, "\n  %d. [%s / %s / %s] %s\n", i+1, f.Layer, f.Severity, f.Confidence, f.ID)
			line("     ", f.Finding)
			if f.NextStep != "" {
				line("     next: ", f.NextStep)
			}
			if len(f.Evidence) > 0 {
				line("     evidence: ", factLine(f.Evidence))
			}
		}
	} else {
		sec("WHAT WAS FOUND")
		line("  ", "No rule fired. That is not the same as healthy — read the two "+
			"sections below before closing this.")
	}

	// ---- ruled out --------------------------------------------------------
	// The section that saves the next person an hour.
	var ok, unknown, failed []string
	for _, s := range t.Segments {
		switch s[1] {
		case "ok":
			ok = append(ok, fmt.Sprintf("%s — %s", s[0], s[2]))
		case "fail":
			failed = append(failed, fmt.Sprintf("%s — %s", s[0], s[2]))
		default:
			unknown = append(unknown, fmt.Sprintf("%s — %s", s[0], s[2]))
		}
	}
	if len(failed) > 0 {
		sec("WHERE THE FAULT IS")
		for _, s := range failed {
			line("  * ", s)
		}
	}
	if len(ok) > 0 {
		sec("RULED OUT (measured healthy — do not re-test these)")
		for _, s := range ok {
			line("  * ", s)
		}
	}
	if len(unknown) > 0 {
		sec("COULD NOT BE JUDGED (not innocent — unmeasurable from here)")
		for _, s := range unknown {
			line("  * ", s)
		}
	}

	// ---- not checked ------------------------------------------------------
	var notRun []string
	for name, res := range t.Snapshot.Collectors {
		if res.Status != schema.StatusOK {
			reason := res.Reason
			if reason == "" {
				reason = "no reason recorded"
			}
			notRun = append(notRun, fmt.Sprintf("%s (%s) — %s", name, res.Status, reason))
		}
	}
	sort.Strings(notRun)
	if len(notRun) > 0 {
		sec("NOT CHECKED (these are NOT green — nobody measured them)")
		for _, n := range notRun {
			line("  * ", n)
		}
	}

	// ---- footer -----------------------------------------------------------
	b.WriteString("\n" + strings.Repeat("=", ticketWidth) + "\n")
	line("", "Collected read-only. netdiag makes no changes to the machine it runs "+
		"on: every item above was observed, not altered.")
	return b.String()
}

// hang wraps s to width with a HANGING indent: the prefix appears once, and
// continuation lines are padded to the same column. The shared wrap() hard-codes
// a 5-space continuation for the terminal report, which turned "next: " into a
// prefix repeated down the left margin — unreadable, and worse, it made a
// pasted ticket look machine-mangled to whoever received it.
func hang(prefix, s string, width int) string {
	pad := strings.Repeat(" ", len([]rune(prefix)))
	avail := width - len([]rune(prefix))
	if avail < 20 { // pathological prefix: do not wrap into a column of one word
		avail = 20
	}
	var b strings.Builder
	col, first := 0, true
	for _, w := range strings.Fields(s) {
		switch {
		case first:
			b.WriteString(prefix + w)
			col, first = len([]rune(w)), false
		case col+1+len([]rune(w)) > avail:
			b.WriteString("\n" + pad + w)
			col = len([]rune(w))
		default:
			b.WriteString(" " + w)
			col += 1 + len([]rune(w))
		}
	}
	if first { // nothing to say
		return ""
	}
	return b.String() + "\n"
}

// factLine renders evidence compactly and deterministically — a ticket that
// reorders its own evidence between runs cannot be diffed.
func factLine(m map[string]any) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, m[k]))
	}
	return strings.Join(parts, ", ")
}
