"""One-file interactive HTML report (spec §14.4).

A single self-contained .html: inline CSS and JS, zero external
requests, works from a USB stick with no network. Email it, attach it
to a ticket, open it in five years — it still renders.

Structure follows how someone actually reads a report: the verdict
first in plain language, then the score and coverage, then the detail,
then the evidence behind the detail. A reader who stops after the first
screen should still have the right impression.

Security (spec §13): every value originating from the snapshot passes
through esc(). Hostnames, log lines, SSIDs and volume labels are all
just text some other process chose, and a report gets emailed around —
so none of it is ever treated as markup.

Emoji are permitted here and only here. §14.2 forbids them in terminal
output because consoles mangle them; a browser does not. Severity is
still never signalled by colour alone — every badge carries a text
label, and the print stylesheet assumes no colour at all.
"""

import html
import json

SEVERITY_META = {
    "critical": ("FAIL", "sev-critical"),
    "warning": ("WARN", "sev-warning"),
}

LEVEL_META = {
    "ok": ("ALL CLEAR", "v-ok"),
    "warning": ("NEEDS ATTENTION", "v-warn"),
    "critical": ("ACTION REQUIRED", "v-crit"),
}

CSS = """
:root{--bg:#0f1115;--card:#181b22;--card2:#1f232c;--line:#2a2f3a;--fg:#e8ebf2;
--muted:#98a2b8;--crit:#ff5f5f;--warn:#ffb020;--ok:#3ecf8e;--info:#6b7488;--accent:#6ea8fe}
@media(prefers-color-scheme:light){:root{--bg:#f6f7f9;--card:#fff;--card2:#f0f2f5;
--line:#e2e5ea;--fg:#1a1d23;--muted:#5c6577;--info:#8a93a6}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 -apple-system,BlinkMacSystemFont,
"Segoe UI",Roboto,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased}
.wrap{max-width:920px;margin:0 auto;padding:36px 20px 72px}
header{margin-bottom:28px}
h1{font-size:20px;margin:0 0 6px;font-weight:650}
.sub{color:var(--muted);font-size:13px}
.sub code{color:var(--fg);font-size:12px}
h2{font-size:12px;text-transform:uppercase;letter-spacing:.09em;color:var(--muted);
margin:34px 0 12px;font-weight:700}

/* verdict */
.verdict{border-radius:14px;padding:22px 24px;margin-bottom:20px;border:1px solid var(--line);
background:var(--card);border-left-width:5px}
.verdict.v-ok{border-left-color:var(--ok)}
.verdict.v-warn{border-left-color:var(--warn)}
.verdict.v-crit{border-left-color:var(--crit)}
.vlabel{font-size:11px;font-weight:800;letter-spacing:.1em;margin-bottom:9px}
.v-ok .vlabel{color:var(--ok)}.v-warn .vlabel{color:var(--warn)}.v-crit .vlabel{color:var(--crit)}
.vhead{font-size:19px;font-weight:650;line-height:1.35;margin-bottom:8px}
.vdetail{color:var(--muted);font-size:14.5px}
.vaction{margin-top:14px;padding-top:14px;border-top:1px solid var(--line);font-size:14.5px}
.vaction b{color:var(--accent);font-weight:600}
.caveat{margin-top:12px;font-size:13px;color:var(--muted);background:var(--card2);
padding:10px 12px;border-radius:8px}

/* stats */
.stats{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:8px}
.stat{flex:1;min-width:132px;background:var(--card);border:1px solid var(--line);
border-radius:12px;padding:15px 17px}
.stat .n{font-size:26px;font-weight:700;line-height:1.15}
.stat .l{font-size:11.5px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-top:3px}
.n.crit{color:var(--crit)}.n.warn{color:var(--warn)}.n.ok{color:var(--ok)}.n.info{color:var(--info)}

/* cards */
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:15px 17px;margin-bottom:10px}
.chain{border-left:4px solid var(--crit)}
.badge{display:inline-block;font-size:10.5px;font-weight:800;letter-spacing:.07em;
padding:3px 8px;border-radius:5px;margin-right:10px;vertical-align:1px}
.sev-critical{background:var(--crit);color:#2a0505}
.sev-warning{background:var(--warn);color:#291b02}
.sev-ok{background:var(--ok);color:#04241b}
.sev-unknown{background:var(--info);color:#0c0f15}
.finding{font-weight:600}
.conf{color:var(--muted);font-size:12px;font-weight:400;margin-left:7px}
.next{color:var(--muted);font-size:14px;margin-top:7px}
.next::before{content:"\\2192\\00a0\\00a0"}
.story{margin-top:9px;line-height:1.6}
.explains{color:var(--muted);font-size:13px;margin-top:9px}
details{margin-top:11px}
summary{cursor:pointer;color:var(--muted);font-size:12.5px;user-select:none;
padding:3px 0;list-style:none}
summary::-webkit-details-marker{display:none}
summary::before{content:"\\25B8\\00a0\\00a0";display:inline-block;transition:transform .15s}
details[open] summary::before{transform:rotate(90deg)}
summary:hover{color:var(--fg)}
pre{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:13px;
overflow-x:auto;font-size:12px;line-height:1.5;margin:9px 0 0;
font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
ul.plain{list-style:none;padding:0;margin:0}
ul.plain li{padding:9px 0;border-bottom:1px solid var(--line);font-size:14px}
ul.plain li:last-child{border-bottom:none}
.muted{color:var(--muted)}
.note{font-size:13px;color:var(--muted);margin-top:9px}
.btn{background:none;border:1px solid var(--line);color:var(--muted);border-radius:8px;
padding:7px 12px;cursor:pointer;font-size:12.5px;font-family:inherit}
.btn:hover{color:var(--fg);border-color:var(--muted)}
.foot{margin-top:44px;padding-top:20px;border-top:1px solid var(--line);
color:var(--muted);font-size:12.5px}

/* Print: assume no colour survives, so structure must carry meaning. */
@media print{
  :root{--bg:#fff;--card:#fff;--card2:#fff;--fg:#000;--muted:#444;--line:#bbb}
  body{font-size:11pt}
  .wrap{max-width:none;padding:0}
  .btn{display:none}
  details{display:block}
  details summary{display:none}
  .card,.verdict,.stat{break-inside:avoid;page-break-inside:avoid}
  .badge{border:1px solid #000;background:none!important;color:#000!important}
  a[href]::after{content:""}
}
"""

JS = """
(function(){
  var btn = document.querySelector('[data-toggle-all]');
  if (!btn) return;
  btn.addEventListener('click', function(){
    var open = btn.getAttribute('data-open') !== 'true';
    document.querySelectorAll('details').forEach(function(d){ d.open = open; });
    btn.setAttribute('data-open', String(open));
    btn.textContent = open ? 'Collapse all evidence' : 'Expand all evidence';
  });
})();
"""


def esc(value):
    """Everything from the snapshot passes through here (spec §13)."""
    return html.escape(str(value), quote=True)


def _evidence(snapshot, collector_id, label=None):
    if not collector_id:
        return ""
    section = (snapshot.get("sections") or {}).get(collector_id)
    if section is None:
        return ""
    dumped = json.dumps(section, indent=2, sort_keys=True, default=str)
    return (
        f"<details><summary>{esc(label or 'Raw evidence — ' + collector_id)}</summary>"
        f"<pre>{esc(dumped)}</pre></details>"
    )


def render_html(snapshot, findings, worth_checking, not_checked, chains=None,
                diff=None, decoded_codes=None, verdict=None, score=None):
    chains = chains or []
    decoded_codes = decoded_codes or []
    parts = []
    a = parts.append

    a('<!doctype html><html lang="en"><head><meta charset="utf-8">')
    a('<meta name="viewport" content="width=device-width,initial-scale=1">')
    a(f"<title>Diagnostic report — {esc(snapshot.get('hostname', 'unknown'))}</title>")
    a(f"<style>{CSS}</style></head><body><div class=\"wrap\">")

    # --- header ---
    a("<header>")
    a(f"<h1>Diagnostic report — {esc(snapshot.get('hostname', 'unknown'))}</h1>")
    a(
        f'<div class="sub">{esc(snapshot.get("os", "?"))} &middot; collected '
        f'<code>{esc(snapshot.get("collected_at", "?"))}</code> &middot; schema '
        f'<code>{esc(snapshot.get("schema_version", "?"))}</code></div>'
    )
    a("</header>")

    # --- verdict: the one thing a reader should take away ---
    if verdict:
        label, css_class = LEVEL_META.get(verdict["level"], LEVEL_META["ok"])
        a(f'<div class="verdict {css_class}">')
        a(f'<div class="vlabel">{esc(label)}</div>')
        a(f'<div class="vhead">{esc(verdict["headline"])}</div>')
        a(f'<div class="vdetail">{esc(verdict["detail"])}</div>')
        if verdict.get("action"):
            a(f'<div class="vaction"><b>Do this first:</b> {esc(verdict["action"])}</div>')
        if verdict.get("coverage_caveat"):
            a(f'<div class="caveat">{esc(verdict["coverage_caveat"])}</div>')
        a("</div>")

    # --- stats ---
    criticals = sum(1 for f in findings if f["severity"] == "critical")
    warns = sum(1 for f in findings if f["severity"] == "warning")
    total_sections = len(snapshot.get("sections") or {})
    checked = total_sections - len(not_checked)

    a('<div class="stats">')
    if score is not None:
        tone = "ok" if score["score"] >= 85 else ("warn" if score["score"] >= 60 else "crit")
        a(f'<div class="stat"><div class="n {tone}">{score["score"]}</div>'
          f'<div class="l">Health score</div></div>')
    a(f'<div class="stat"><div class="n {"crit" if criticals else "info"}">{criticals}</div>'
      f'<div class="l">Critical</div></div>')
    a(f'<div class="stat"><div class="n {"warn" if warns else "info"}">{warns}</div>'
      f'<div class="l">Warnings</div></div>')
    a(f'<div class="stat"><div class="n {"ok" if not not_checked else "info"}">{checked}/{total_sections}</div>'
      f'<div class="l">Checks run</div></div>')
    a("</div>")

    if score is not None and score.get("deductions"):
        a('<details class="card"><summary>How the score was calculated</summary><pre>'
          + esc("100 starting score\n" + "\n".join(
              f"-{d['amount']:<4} {d['id']}: {d['reason']}" for d in score["deductions"]
          ) + f"\n{'=' * 40}\n{score['score']} final")
          + "</pre></details>")

    # --- baseline diff ---
    if diff is not None:
        a("<h2>Changed since baseline</h2>")
        rows = (
            [esc(line) for line in diff["value_changes"]]
            + [f"<b>New:</b> {esc(fid)}" for fid in diff["new_finding_ids"]]
            + [f"<b>Resolved:</b> {esc(fid)}" for fid in diff["resolved_finding_ids"]]
        )
        if rows:
            a('<div class="card"><ul class="plain">')
            for row in rows:
                a(f"<li>{row}</li>")
            a("</ul></div>")
        else:
            a('<div class="card muted">No differences from baseline.</div>')

    # --- findings ---
    a("<h2>What was found</h2>")

    for chain in chains:
        a('<div class="card chain">')
        a('<span class="badge sev-critical">ROOT CAUSE</span>'
          f'<span class="conf">confidence: {esc(chain["confidence"])}</span>')
        a(f'<div class="story">{esc(chain["story"])}</div>')
        a('<div class="explains">Explains: '
          + ", ".join(esc(m) for m in chain["members"]) + "</div>")
        for cid in chain.get("collectors", []):
            a(_evidence(snapshot, cid))
        a("</div>")

    if not findings and not chains:
        a('<div class="card"><span class="badge sev-ok">OK</span>'
          '<span class="finding">Nothing wrong was found in the checks that ran.</span></div>')

    for f in findings:
        label, css_class = SEVERITY_META.get(f["severity"], ("WARN", "sev-warning"))
        a('<div class="card">')
        a(f'<span class="badge {css_class}">{label}</span>'
          f'<span class="finding">{esc(f["finding"])}</span>'
          f'<span class="conf">confidence: {esc(f["confidence"])}</span>')
        if f.get("next_step"):
            a(f'<div class="next">{esc(f["next_step"])}</div>')
        a(_evidence(snapshot, f.get("collector")))
        a("</div>")

    # --- worth checking ---
    if worth_checking:
        a('<h2>Worth checking <span class="muted">(possible, not confirmed)</span></h2>')
        for f in worth_checking:
            a('<div class="card">')
            a('<span class="badge sev-unknown">CHECK</span>'
              f'<span class="finding">{esc(f["finding"])}</span>')
            if f.get("next_step"):
                a(f'<div class="next">{esc(f["next_step"])}</div>')
            a("</div>")

    # --- decoded codes (§10) ---
    if decoded_codes:
        a("<h2>Error codes found in the logs</h2>")
        for code in decoded_codes:
            a('<div class="card">')
            a('<span class="badge sev-unknown">CODE</span>'
              f'<span class="finding">{esc(code["code"])}</span>'
              f'<span class="conf">{esc(code.get("name") or code.get("meaning", ""))}</span>')
            a(f'<div class="next" style="margin-top:8px">{esc(code["cause"])}</div>')
            a(f'<div class="next">{esc(code["next_step"])}</div>')
            a("</div>")

    # --- coverage: never omitted, even when empty (§3.4) ---
    a("<h2>What was not checked</h2>")
    if not_checked:
        a('<div class="card"><ul class="plain">')
        for cid, status, reason in not_checked:
            a(f'<li><span class="badge sev-unknown">{esc(str(status).upper())}</span>'
              f'<strong>{esc(cid)}</strong> — {esc(reason)}</li>')
        a("</ul></div>")
        a('<div class="note">These were not verified. '
          "The absence of a finding here is not evidence that everything is fine.</div>")
    else:
        a('<div class="card muted">Nothing — every check ran and produced data.</div>')

    a('<div class="foot">'
      '<button class="btn" data-toggle-all data-open="false">Expand all evidence</button>'
      "<p>Self-contained report — no network required, safe to email or archive. "
      "Generated by Diagnostic Companion.</p></div>")

    a(f"</div><script>{JS}</script></body></html>")
    return "".join(parts)
