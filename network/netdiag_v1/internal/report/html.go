package report

// A self-contained HTML report: no CDN, no JavaScript, no fonts to fetch —
// it has to open on a machine whose network is broken, which is the whole
// point of the tool. Everything is inline so the file can be mailed,
// attached to a ticket, or opened from a USB stick.

import (
	"fmt"
	"html"
	"strings"
	"time"

	"netdiag/internal/interpret"
	"netdiag/internal/schema"
)

// RenderHTML builds the report. verdict is the §8 blame headline; segments
// are the per-segment rows (name, status, evidence) so the page can show the
// same table the terminal does.
func RenderHTML(snap *schema.Snapshot, findings []interpret.Finding, kbSource, verdict string,
	segments [][3]string) string {
	var b strings.Builder

	b.WriteString(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>netdiag report — ` + html.EscapeString(snap.Hostname) + `</title><style>
:root{--ok:#1a7f37;--bad:#b42318;--warn:#b54708;--unk:#6b7280;--line:#e5e7eb;--ink:#111827;--soft:#f9fafb}
*{box-sizing:border-box}
body{margin:0;padding:32px 20px;background:#fff;color:var(--ink);
 font:16px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:820px;margin:0 auto}
h1{font-size:22px;margin:0 0 4px} h2{font-size:17px;margin:32px 0 12px}
.meta{color:var(--unk);font-size:13px;margin-bottom:24px}
.verdict{border-left:4px solid var(--ink);background:var(--soft);padding:14px 16px;
 border-radius:0 6px 6px 0;margin:0 0 8px;font-size:17px}
table{border-collapse:collapse;width:100%;font-size:15px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--unk);font-weight:600}
.ok{color:var(--ok);font-weight:600}.bad{color:var(--bad);font-weight:600}
.warn{color:var(--warn);font-weight:600}.unk{color:var(--unk);font-weight:600}
.f{border:1px solid var(--line);border-radius:6px;padding:14px 16px;margin-bottom:10px}
.f .sev{font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.f .next{margin-top:8px;padding-top:8px;border-top:1px dashed var(--line)}
.f .ev{color:var(--unk);font-size:13px;font-family:ui-monospace,Consolas,monospace;margin-top:6px}
.note{background:var(--soft);border-radius:6px;padding:14px 16px;color:#374151;font-size:14px}
ul{margin:8px 0 0;padding-left:20px}
footer{margin-top:36px;padding-top:14px;border-top:1px solid var(--line);
 color:var(--unk);font-size:13px}
</style></head><body><div class="wrap">`)

	fmt.Fprintf(&b, "<h1>Network report — %s</h1>", html.EscapeString(snap.Hostname))
	fmt.Fprintf(&b, `<div class="meta">%s &middot; %s &middot; netdiag %s &middot; knowledge base: %s</div>`,
		html.EscapeString(snap.CollectedAt.Local().Format("Monday 2 January 2006, 15:04")),
		html.EscapeString(snap.OS), html.EscapeString(snap.ToolVersion), html.EscapeString(kbSource))

	if verdict != "" {
		fmt.Fprintf(&b, `<h2>Verdict</h2><p class="verdict">%s</p>`, html.EscapeString(verdict))
	}
	if len(segments) > 0 {
		b.WriteString(`<table><tr><th>Where</th><th>State</th><th>What was measured</th></tr>`)
		for _, s := range segments {
			fmt.Fprintf(&b, `<tr><td>%s</td><td class="%s">%s</td><td>%s</td></tr>`,
				html.EscapeString(s[0]), cssFor(s[1]), markFor(s[1]), html.EscapeString(s[2]))
		}
		b.WriteString(`</table>`)
	}

	// Layer card — same data as the terminal report.
	b.WriteString(`<h2>By network layer</h2><table><tr><th>Layer</th><th>State</th><th>Detail</th></tr>`)
	checked := map[string]bool{}
	for name, res := range snap.Collectors {
		if res.Status == schema.StatusOK {
			for _, l := range collectorLayers[name] {
				checked[l] = true
			}
		}
	}
	worst := map[string]interpret.Finding{}
	for _, f := range findings {
		if cur, ok := worst[f.Layer]; !ok || sevRankHTML(f.Severity) > sevRankHTML(cur.Severity) {
			worst[f.Layer] = f
		}
	}
	for _, l := range layerOrder {
		state, detail := "unknown", "not checked in this run — this is not a clean bill of health"
		if f, bad := worst[l]; bad {
			state, detail = f.Severity, f.Finding
		} else if checked[l] {
			state, detail = "ok", "clean (within what this run measures)"
		}
		fmt.Fprintf(&b, `<tr><td>%s&nbsp;&nbsp;%s</td><td class="%s">%s</td><td>%s</td></tr>`,
			l, html.EscapeString(layerNames[l]), cssFor(state), markFor(state), html.EscapeString(detail))
	}
	b.WriteString(`</table>`)

	if len(findings) > 0 {
		fmt.Fprintf(&b, `<h2>What was found (%d)</h2>`, len(findings))
		for _, f := range findings {
			fmt.Fprintf(&b, `<div class="f"><div class="sev %s">%s &middot; %s &middot; confidence: %s</div>`,
				cssFor(f.Severity), html.EscapeString(strings.ToUpper(f.Severity)),
				html.EscapeString(f.Layer), html.EscapeString(f.Confidence))
			fmt.Fprintf(&b, `<div>%s</div>`, html.EscapeString(f.Finding))
			fmt.Fprintf(&b, `<div class="next"><strong>Next step:</strong> %s</div>`,
				html.EscapeString(f.NextStep))
			if len(f.Evidence) > 0 {
				var ev []string
				for k, v := range f.Evidence {
					ev = append(ev, fmt.Sprintf("%s=%v", k, v))
				}
				fmt.Fprintf(&b, `<div class="ev">%s &nbsp;(rule: %s)</div>`,
					html.EscapeString(strings.Join(ev, "  ")), html.EscapeString(f.ID))
			}
			b.WriteString(`</div>`)
		}
	} else {
		b.WriteString(`<h2>What was found</h2><p class="note">Nothing crossed a threshold in this run.
		 That is evidence, not proof: a fault that comes and goes may simply not have happened
		 while this ran.</p>`)
	}

	// The honest half — never omitted, because a missing measurement that
	// looks like a pass is the failure mode this whole tool exists to avoid.
	var notRun []string
	for name, res := range snap.Collectors {
		if res.Status != schema.StatusOK {
			reason := res.Reason
			if reason == "" {
				reason = string(res.Status)
			}
			notRun = append(notRun, fmt.Sprintf("%s — %s", name, reason))
		}
	}
	if len(notRun) > 0 {
		b.WriteString(`<h2>Not checked, or checked and degraded</h2>
		<div class="note">These are <strong>not</strong> green. They were skipped, timed out, or
		 needed privileges this run did not have.<ul>`)
		for _, n := range notRun {
			fmt.Fprintf(&b, `<li>%s</li>`, html.EscapeString(n))
		}
		b.WriteString(`</ul></div>`)
	}

	fmt.Fprintf(&b, `<footer>Read-only run: nothing was configured, released, or sent beyond this
	 machine's own gateway and resolver. Generated %s by netdiag %s.</footer></div></body></html>`,
		time.Now().Local().Format("2006-01-02 15:04"), html.EscapeString(snap.ToolVersion))
	return b.String()
}

func cssFor(state string) string {
	switch state {
	case "ok":
		return "ok"
	case "critical":
		return "bad"
	case "warning":
		return "warn"
	case "fail":
		return "bad"
	case "info":
		return "unk"
	}
	return "unk"
}

func markFor(state string) string {
	switch state {
	case "ok":
		return "OK"
	case "fail", "critical":
		return "PROBLEM"
	case "warning":
		return "WARNING"
	case "info":
		return "note"
	}
	return "not measured"
}

func sevRankHTML(s string) int {
	switch s {
	case "critical":
		return 3
	case "warning":
		return 2
	}
	return 1
}
