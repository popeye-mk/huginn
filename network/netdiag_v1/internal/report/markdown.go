// Markdown renderer (§18 v1: "terminal + Markdown output") — the same
// layer report and findings, shaped for a ticket or a wiki paste.
package report

import (
	"fmt"
	"sort"
	"strings"

	"netdiag/internal/interpret"
	"netdiag/internal/schema"
)

func RenderMarkdown(snap *schema.Snapshot, findings []interpret.Finding, kbSource, verdict string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# netdiag v1.1 — passive scan of %s\n\n", snap.Hostname)
	fmt.Fprintf(&b, "*OS:* %s · *collected:* %s · *schema:* %s · *KB:* %s\n\n",
		snap.OS, snap.CollectedAt.Format("2006-01-02 15:04:05 MST"), snap.SchemaVersion, kbSource)
	if verdict != "" {
		fmt.Fprintf(&b, "> **Verdict (§8):** %s\n\n", verdict)
	}

	checked := map[string]bool{}
	for name, res := range snap.Collectors {
		if res.Status == schema.StatusOK {
			for _, l := range collectorLayers[name] {
				checked[l] = true
			}
		}
	}
	dirty := map[string][]string{}
	for _, f := range findings {
		dirty[f.Layer] = append(dirty[f.Layer], shortLine(f.Finding))
	}

	b.WriteString("## Layer report\n\n")
	b.WriteString("| Layer | | Status |\n|---|---|---|\n")
	for _, l := range layerOrder {
		switch {
		case len(dirty[l]) > 0:
			fmt.Fprintf(&b, "| %s | %s | ✗ %s |\n", l, layerNames[l], strings.Join(dirty[l], "; "))
		case checked[l]:
			fmt.Fprintf(&b, "| %s | %s | ✓ clean (within what v1 measures) |\n", l, layerNames[l])
		default:
			fmt.Fprintf(&b, "| %s | %s | – not checked |\n", l, layerNames[l])
		}
	}
	b.WriteString("\n")

	if len(findings) == 0 {
		b.WriteString("## Findings\n\nNone. The layers marked ✓ look healthy from this machine.\n\n")
	} else {
		fmt.Fprintf(&b, "## Findings (%d)\n\n", len(findings))
		for i, f := range findings {
			fmt.Fprintf(&b, "%d. **[%s | %s | %s]** %s\n", i+1, f.Layer, f.Severity, f.Confidence, f.Finding)
			if f.NextStep != "" {
				fmt.Fprintf(&b, "   - *Next step:* %s\n", f.NextStep)
			}
			fmt.Fprintf(&b, "   - *Evidence:* `%s` (rule `%s`)\n", kv(f.Evidence), f.ID)
		}
		b.WriteString("\n")
	}

	var notRun []string
	for name, res := range snap.Collectors {
		if res.Status != schema.StatusOK {
			notRun = append(notRun, fmt.Sprintf("`%s` (%s: %s)", name, res.Status, res.Reason))
		}
	}
	sort.Strings(notRun)
	if len(notRun) > 0 {
		b.WriteString("## Not checked / degraded — these are NOT green\n\n")
		for _, n := range notRun {
			fmt.Fprintf(&b, "- %s\n", n)
		}
		b.WriteString("\n")
	}
	b.WriteString("---\n*Read-only run: nothing was configured, released, or sent beyond " +
		"this machine's own gateway, resolver, and the known-good public anchors (spec §3, passive tier).*\n")
	return b.String()
}
