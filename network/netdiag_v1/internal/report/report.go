// Package report renders the signature output: the clean/not-clean-per-layer
// card (spec §5.1), then findings, then the honest "not checked" section.
package report

import (
	"fmt"
	"sort"
	"strings"

	"netdiag/internal/interpret"
	"netdiag/internal/schema"
)

// Which OSI layers each collector vouches for when it ran ok.
var collectorLayers = map[string][]string{
	"link":           {"L1"},
	"wifi":           {"L1"},
	"nic_power":      {"L1"},
	"event_history":  {"L1"},
	"neigh":          {"L2"},
	"addressing":     {"L3"},
	"routing":        {"L3"},
	"gateway_ping":   {"L3"},
	"net_quality":    {"L3"},
	"ipv6":           {"L3"},
	"vpn":            {"L3"},
	"sockets":        {"L4"},
	"tcp_stats":      {"L4"},
	"firewall":       {"L4"},
	"dns":            {"L7"},
	"dns_extra":      {"L7"},
	"captive_portal": {"L7"},
	"proxy":          {"L7"},
	"time_sync":      {"L7"},
	"ad_state":       {"L7"},
	"hygiene":        {"L4", "L7"},
	"print_spooler":  {"L7"},
}

var layerNames = map[string]string{
	"L1": "Physical", "L2": "Data link", "L3": "Network",
	"L4": "Transport", "L7": "Application",
}

var layerOrder = []string{"L1", "L2", "L3", "L4", "L7"}

// Render renders the terminal report. blame (§8, may be empty) goes above
// everything else — the verdict is the headline, not a footnote.
func Render(snap *schema.Snapshot, findings []interpret.Finding, kbSource, blame string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "netdiag v1.1 — passive scan of %s (%s)  schema %s  kb: %s\n",
		snap.Hostname, snap.OS, snap.SchemaVersion, kbSource)
	b.WriteString(strings.Repeat("─", 72) + "\n\n")
	if blame != "" {
		b.WriteString(blame + "\n")
	}

	// Layer status: checked layers start clean, findings dirty them,
	// unchecked layers are named as unchecked — absence is never health.
	checked := map[string]bool{}
	for name, res := range snap.Collectors {
		if res.Status == schema.StatusOK {
			for _, l := range collectorLayers[name] {
				checked[l] = true
			}
		}
	}
	// Bug #32 (Zorin, 0.9.22, spotted in the field output): the layer marks
	// treated every finding as damage, so an INFO note whose own text said
	// "normally ignore it" put a ✗ on L1 Physical. A reader scanning the marks
	// saw "physical layer: fail" for something the finding called harmless.
	// The ✗ is a claim of a fault; info is by definition not one, so notes get
	// their own mark and cannot dirty a layer.
	dirty := map[string][]string{}
	notes := map[string][]string{}
	for _, f := range findings {
		if f.Severity == "info" {
			notes[f.Layer] = append(notes[f.Layer], shortLine(f.Finding))
		} else {
			dirty[f.Layer] = append(dirty[f.Layer], shortLine(f.Finding))
		}
	}

	b.WriteString("  Layer report\n")
	for _, l := range layerOrder {
		name := fmt.Sprintf("%-4s%-12s", l, layerNames[l])
		switch {
		case len(dirty[l]) > 0:
			fmt.Fprintf(&b, "  %s ✗  %s\n", name, dirty[l][0])
			for _, extra := range dirty[l][1:] {
				fmt.Fprintf(&b, "  %s      %s\n", strings.Repeat(" ", 16), extra)
			}
		case len(notes[l]) > 0:
			// Notes only: the layer is not failing, and saying so matters more
			// than the note does. The note is still one line below.
			fmt.Fprintf(&b, "  %s i  no fault — but note: %s\n", name, notes[l][0])
			for _, extra := range notes[l][1:] {
				fmt.Fprintf(&b, "  %s      %s\n", strings.Repeat(" ", 16), extra)
			}
		case checked[l]:
			fmt.Fprintf(&b, "  %s ✓  clean (within what v1 measures)\n", name)
		default:
			fmt.Fprintf(&b, "  %s –  not checked\n", name)
		}
	}
	b.WriteString("\n")

	if len(findings) == 0 {
		b.WriteString("  No findings. The layers marked ✓ look healthy from this machine.\n\n")
	} else {
		fmt.Fprintf(&b, "  Findings (%d)\n", len(findings))
		for i, f := range findings {
			fmt.Fprintf(&b, "  %d. [%s|%s|%s] %s\n", i+1, f.Layer, f.Severity, f.Confidence, f.Finding)
			if f.NextStep != "" {
				fmt.Fprintf(&b, "     → next step: %s\n", f.NextStep)
			}
			fmt.Fprintf(&b, "     evidence: %s   (rule: %s)\n", kv(f.Evidence), f.ID)
		}
		b.WriteString("\n")
	}

	// The honesty section.
	var notRun []string
	for name, res := range snap.Collectors {
		if res.Status != schema.StatusOK {
			notRun = append(notRun, fmt.Sprintf("%s (%s: %s)", name, res.Status, res.Reason))
		}
	}
	sort.Strings(notRun)
	if len(notRun) > 0 {
		b.WriteString("  Not checked / degraded — these are NOT green:\n")
		for _, n := range notRun {
			fmt.Fprintf(&b, "   • %s\n", n)
		}
		b.WriteString("\n")
	}
	b.WriteString("  Read-only run: nothing was configured, released, or sent beyond this\n")
	b.WriteString("  machine's own gateway and resolver (spec §3, passive tier).\n")
	return b.String()
}

// RenderForUser (§6.2): the same findings, jargon-free — fit to paste into
// a ticket-closure note. Layer/confidence machinery stripped, not translated.
func RenderForUser(findings []interpret.Finding) string {
	var b strings.Builder
	b.WriteString("  In plain language (for the ticket / the user)\n")
	b.WriteString("  " + strings.Repeat("─", 62) + "\n")
	if len(findings) == 0 {
		b.WriteString("  Everything this tool can measure from your computer looks healthy\n" +
			"  right now. If the problem continues, it is likely intermittent or on\n" +
			"  the far side — worth rechecking while it is actually happening.\n")
		return b.String()
	}
	n := 0
	for _, f := range findings {
		text := f.ForUser
		if text == "" {
			text = f.Finding
		}
		n++
		fmt.Fprintf(&b, "  %d. %s\n", n, wrap(text, 68))
	}
	return b.String()
}

func wrap(s string, width int) string {
	words := strings.Fields(s)
	var b strings.Builder
	line := 0
	for i, w := range words {
		if line+len(w)+1 > width && line > 0 {
			b.WriteString("\n     ")
			line = 0
		} else if i > 0 {
			b.WriteString(" ")
			line++
		}
		b.WriteString(w)
		line += len(w)
	}
	return b.String()
}

func kv(m map[string]any) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s=%v", k, m[k])
	}
	return strings.Join(parts, " ")
}

func shortLine(s string) string {
	for _, sep := range []string{". ", " — ", " - "} {
		if i := strings.Index(s, sep); i > 10 {
			return s[:i]
		}
	}
	if len(s) > 60 {
		return s[:60] + "…"
	}
	return s
}
