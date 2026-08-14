package report

import (
	"strings"
	"testing"
	"time"

	"netdiag/internal/interpret"
	"netdiag/internal/schema"
)

// A ticket is read by someone who was not there. Every property below exists
// to stop that reader drawing a conclusion the evidence does not support.

func sampleTicket() Ticket {
	return Ticket{
		Snapshot: &schema.Snapshot{
			Tool: "netdiag", ToolVersion: "test", Hostname: "desk-14", OS: "linux",
			CollectedAt: time.Date(2026, 7, 19, 9, 30, 0, 0, time.UTC),
			Collectors: map[string]schema.CollectorResult{
				"link":     {Status: schema.StatusOK, Data: map[string]any{"link_up": true}},
				"firewall": {Status: schema.StatusSkipped, Reason: "ruleset not readable unprivileged"},
				"ad_state": {Status: schema.StatusTimeout, Reason: "collector exceeded its timeout"},
			},
		},
		Findings: []interpret.Finding{{
			Rule: interpret.Rule{
				ID: "upstream_lossy", Layer: "L3", Severity: "critical", Confidence: "likely",
				Finding:  "12% packet loss beyond the gateway while the gateway itself is clean.",
				NextStep: "Escalate to the ISP with these figures; the LAN is not the cause.",
			},
			Evidence: map[string]any{"upstream_loss_pct": 12, "gateway_loss_pct": 0},
		}},
		Symptom: "slow", Verdict: "the problem is past your gateway",
		FirstBreak: "L3: upstream loss",
		Segments: [][3]string{
			{"This machine", "ok", "link, addressing and local config look healthy"},
			{"Your LAN", "ok", "gateway answers in 1.2 ms, 0% loss"},
			{"Your ISP / WAN", "fail", "12% loss beyond the gateway"},
		},
		KBSource: "embedded",
	}
}

// The section that saves the next engineer an hour: what was measured healthy,
// stated explicitly so nobody re-tests it.
func TestTicketSaysWhatWasRuledOut(t *testing.T) {
	out := RenderTicket(sampleTicket())
	if !strings.Contains(out, "RULED OUT") {
		t.Fatal("no ruled-out section — the next person starts from zero")
	}
	for _, want := range []string{"This machine", "Your LAN", "gateway answers in 1.2 ms"} {
		if !strings.Contains(out, want) {
			t.Errorf("ruled-out evidence missing %q", want)
		}
	}
	// The healthy segments must not be mixed in with the faulty one.
	ruled := out[strings.Index(out, "RULED OUT"):]
	if strings.Contains(ruled[:strings.Index(ruled, "NOT CHECKED")], "12% loss") {
		t.Error("the failing segment was listed as ruled out")
	}
}

// The property this whole project is built on, in the format most likely to be
// read by someone who will act on it without asking questions.
func TestTicketNeverImpliesUncheckedThingsWereFine(t *testing.T) {
	out := RenderTicket(sampleTicket())
	if !strings.Contains(out, "NOT CHECKED") {
		t.Fatal("a ticket with skipped collectors did not say so")
	}
	for _, want := range []string{"firewall", "ruleset not readable", "ad_state", "timeout"} {
		if !strings.Contains(out, want) {
			t.Errorf("not-checked section missing %q", want)
		}
	}
	if !strings.Contains(out, "NOT green") {
		t.Error("the not-checked heading lost the words that stop it being read as a pass")
	}
}

// A clean run is the dangerous case: nothing fired, and the reader is one
// sentence away from closing the ticket as "no fault found".
func TestCleanTicketDoesNotReadAsAllClear(t *testing.T) {
	tk := sampleTicket()
	tk.Findings = nil
	tk.Verdict = ""
	out := RenderTicket(tk)

	if !strings.Contains(out, "not the same as healthy") {
		t.Error("an empty findings list was presented without its qualifier")
	}
	if strings.Contains(out, "no problems") || strings.Contains(out, "everything is fine") {
		t.Errorf("clean ticket over-claimed:\n%s", out)
	}
	if !strings.Contains(out, "No verdict") {
		t.Error("a ticket with no verdict silently omitted the verdict section")
	}
}

// Segments that could not be judged are neither guilty nor innocent, and the
// wording has to carry that or the reader will treat them as cleared.
func TestUnjudgedSegmentsAreNotFiledAsRuledOut(t *testing.T) {
	tk := sampleTicket()
	tk.Segments = [][3]string{
		{"This machine", "ok", "healthy"},
		{"Your ISP / WAN", "unknown", "upstream path was not measured"},
	}
	out := RenderTicket(tk)
	if !strings.Contains(out, "COULD NOT BE JUDGED") {
		t.Fatal("unknown segment was not given its own section")
	}
	if !strings.Contains(out, "not innocent") {
		t.Error("the unknown section did not say that unmeasured is not cleared")
	}
	ruled := out[strings.Index(out, "RULED OUT"):]
	if strings.Contains(ruled[:strings.Index(ruled, "COULD NOT")], "ISP") {
		t.Error("an unmeasured segment was listed as ruled out")
	}
}

// It gets pasted into ticket systems. Fixed width, no markdown, and a finding's
// next step must survive the wrapping intact.
func TestTicketIsPasteableAndKeepsItsNextStep(t *testing.T) {
	out := RenderTicket(sampleTicket())
	for _, line := range strings.Split(out, "\n") {
		if len([]rune(line)) > ticketWidth+4 {
			t.Errorf("line too wide for a ticket field (%d): %q", len([]rune(line)), line)
		}
	}
	for _, md := range []string{"**", "##", "|---"} {
		if strings.Contains(out, md) {
			t.Errorf("markdown %q leaked into a plain-text ticket", md)
		}
	}
	flat := strings.Join(strings.Fields(out), " ")
	if !strings.Contains(flat, "Escalate to the ISP with these figures") {
		t.Error("the next step did not survive wrapping")
	}
	if !strings.Contains(flat, "gateway_loss_pct=0, upstream_loss_pct=12") {
		t.Error("evidence is missing or not in deterministic order — tickets must diff cleanly")
	}
}

// The read-only promise is why this tool is safe to run on a customer's
// machine, and the ticket is often the only artefact that leaves it.
func TestTicketCarriesTheReadOnlyPromise(t *testing.T) {
	if !strings.Contains(RenderTicket(sampleTicket()), "read-only") {
		t.Error("the ticket does not state that nothing was changed")
	}
}

// hang is what makes the whole thing readable; it must not repeat the prefix
// down the margin or lose a word.
func TestHangingIndentKeepsEveryWordAndPrefixesOnce(t *testing.T) {
	const s = "Escalate to the ISP with these figures; the LAN is not the cause and has been measured clean."
	got := hang("     next: ", s, 60)

	if strings.Count(got, "next:") != 1 {
		t.Errorf("prefix repeated down the margin:\n%s", got)
	}
	if strings.Join(strings.Fields(got), " ") != "next: "+s {
		t.Errorf("words changed:\n%s", got)
	}
	if hang("  ", "", 60) != "" {
		t.Error("an empty string produced a stray prefix line")
	}
}
