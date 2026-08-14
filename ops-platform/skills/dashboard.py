"""`dashboard` skill — the Network Guard pane of glass (G5).

Renders the guard's current state — every known device, its name, and the
ports it leaves open — into one self-contained HTML file the operator opens
in a browser. It is a **snapshot and read-only by construction**: a static
file with no scripts that act, no controls, nothing that can touch the
network. It reads only the baselines the guard verbs already wrote.

Honest empty-state: with no census yet the page says "no scan yet — run a
census," never "the LAN is clean."
"""

import html
import json
import os
from datetime import datetime, timezone
from typing import Any

from domains.census import load_baseline
from domains.dashboard import build_state
from domains.exposure import load_exposure_baseline
from domains.timeline import summarize
from platform_support import hostname

_CENSUS_BASELINE = os.path.join("data", "census", "lan_baseline.json")
_EXPO_BASELINE = os.path.join("data", "census", "exposure_baseline.json")
_TIMELINE_JOURNAL = os.path.join("data", "census", "guard_events.json")
_OUT = os.path.join("data", "census", "dashboard.html")

_HEAT_COLOR = {"critical": "#e0533d", "warning": "#d9a441", "clear": "#3fbf7f"}
_CHANGE_CLASS = {"critical": "crit", "warning": "warn", "info": "info"}


def _short_ts(ts: str) -> str:
    return ts.replace("T", " ")[:16] if ts else ""


def _changes_html(summary) -> str:
    """The 'recent changes' section (G7 timeline in the dashboard, G10)."""
    if not summary.has_history:
        return ("<p class='muted'>No guard history yet — the scheduled patrol "
                "writes it as it runs. (Not an all-clear.)</p>")
    if not summary.changes:
        return "<p class='muted'>No changes on the LAN in the last 7 days.</p>"
    items = []
    for c in summary.changes:
        cls = _CHANGE_CLASS.get(c.severity, "info")
        span = (f"{c.count}× · last {_short_ts(c.last_ts)}" if c.count > 1
                else _short_ts(c.last_ts))
        items.append(
            f"<li class='chg {cls}'>[{html.escape(c.severity)}] "
            f"{html.escape(c.message)} <span class='when'>{html.escape(span)}</span></li>")
    return "<ul class='changes'>" + "".join(items) + "</ul>"


def _row_html(d: dict) -> str:
    color = _HEAT_COLOR.get(d["heat"], "#888")
    ports = ", ".join(f"{n} ({p})" for n, p in
                      zip(d["port_names"], d["open_ports"])) or "—"
    return (
        "<tr>"
        f"<td><span class='dot' style='background:{color}'></span></td>"
        f"<td class='ip'>{html.escape(d['ip'])}</td>"
        f"<td>{html.escape(d['label'])}</td>"
        f"<td class='kind'>{html.escape(d.get('device_type', ''))}</td>"
        f"<td class='mac'>{html.escape(d['mac'])}</td>"
        f"<td>{html.escape(ports)}</td>"
        f"<td class='seen'>{html.escape((d['last_seen'] or '')[:19])}</td>"
        "</tr>"
    )


def _render_html(state, build_stamp="", changes_html="") -> str:
    s = state.as_dict()
    rows = "\n".join(_row_html(d) for d in s["devices"])
    if not s["devices"]:
        rows = ("<tr><td colspan='7' class='empty'>No scan yet — run a "
                "census first. (An empty dashboard is not a clean bill of "
                "health.)</td></tr>")
    payload = html.escape(json.dumps(s, ensure_ascii=False))
    return _PAGE.format(
        machine=html.escape(s["machine_id"]),
        generated=html.escape(s["generated_at"]),
        n=s["device_count"], exposed=s["exposed_count"],
        crit=s["critical_count"], rows=rows, changes=changes_html,
        stamp=html.escape(build_stamp), payload=payload,
    )


def skill_dashboard(args: str, speaker: Any = None) -> str:
    """Render the guard's current state to a read-only HTML dashboard."""
    del args, speaker
    machine_id = hostname()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    # G10: fold the G7 change-timeline into the pane of glass. The skill reads
    # the journal (the dashboard domain stays baseline-only, no cross-domain).
    summary = summarize(_TIMELINE_JOURNAL, since_days=7)
    changes = [{"severity": c.severity, "message": c.message,
                "last": c.last_ts[:19], "count": c.count} for c in summary.changes]
    state = build_state(
        load_baseline(_CENSUS_BASELINE),
        load_exposure_baseline(_EXPO_BASELINE),
        machine_id=machine_id, generated_at=now,
        recent_changes=changes,
    )
    os.makedirs(os.path.dirname(_OUT), exist_ok=True)
    tmp = _OUT + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(_render_html(state, changes_html=_changes_html(summary)))
    os.replace(tmp, _OUT)

    return (f"  NETWORK GUARD DASHBOARD — {machine_id}\n"
            f"  {'=' * 58}\n"
            f"  {state.device_count} device(s) · "
            f"{state.exposed_count} with an open port · "
            f"{state.critical_count} critical\n"
            f"\n"
            f"  Read-only snapshot — nothing on the page can act.\n"
            f"  (In the console, click 'Open the dashboard'. From a terminal, "
            f"open {_OUT} in a browser.)")


# A self-contained page: inline CSS, one <script> that only *reads* an
# embedded JSON blob to draw the heatmap bar. No fetch, no controls.
_PAGE = """<!doctype html><html><head><meta charset="utf-8">
<title>Network Guard — {machine}</title>
<style>
 body{{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;
   background:#0f1216;color:#e6e9ee;margin:0;padding:24px;}}
 h1{{font-size:18px;margin:0 0 2px;}}
 .sub{{color:#8b93a1;font-size:12px;margin-bottom:18px;}}
 .cards{{display:flex;gap:12px;margin-bottom:20px;flex-wrap:wrap;}}
 .card{{background:#171b21;border:1px solid #262c35;border-radius:10px;
   padding:12px 18px;min-width:120px;}}
 .card b{{font-size:22px;display:block;}}
 .card.crit b{{color:#e0533d;}} .card.warn b{{color:#d9a441;}}
 table{{width:100%;border-collapse:collapse;background:#171b21;
   border:1px solid #262c35;border-radius:10px;overflow:hidden;}}
 th,td{{text-align:left;padding:9px 12px;border-bottom:1px solid #21262e;}}
 th{{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#8b93a1;}}
 .dot{{display:inline-block;width:10px;height:10px;border-radius:50%;}}
 .ip{{font-variant-numeric:tabular-nums;}}
 .mac,.seen{{color:#8b93a1;font-size:12px;font-family:ui-monospace,monospace;}}
 .kind{{color:#a9b4c2;font-size:12px;}}
 .empty{{color:#8b93a1;text-align:center;padding:30px;}}
 h2{{font-size:13px;text-transform:uppercase;letter-spacing:.5px;color:#8b93a1;
   margin:24px 0 8px;}}
 .muted{{color:#8b93a1;font-size:13px;}}
 .changes{{list-style:none;padding:0;margin:0;}}
 .changes .chg{{background:#171b21;border:1px solid #262c35;border-left:3px solid #3fbf7f;
   border-radius:8px;padding:8px 12px;margin-bottom:6px;font-size:13px;}}
 .changes .chg.crit{{border-left-color:#e0533d;}}
 .changes .chg.warn{{border-left-color:#d9a441;}}
 .changes .when{{color:#5b6472;font-size:11px;margin-left:6px;}}
 footer{{color:#5b6472;font-size:11px;margin-top:16px;}}
</style></head><body>
<h1>Network Guard — {machine}</h1>
<div class="sub">Snapshot {generated} · read-only</div>
<div class="cards">
 <div class="card"><b>{n}</b>devices</div>
 <div class="card warn"><b>{exposed}</b>with open port</div>
 <div class="card crit"><b>{crit}</b>critical</div>
</div>
<table>
 <thead><tr><th></th><th>IP</th><th>Device</th><th>Type</th><th>MAC</th>
   <th>Open ports</th><th>Last seen</th></tr></thead>
 <tbody>
{rows}
 </tbody>
</table>
<h2>Recent changes (last 7 days)</h2>
{changes}
<footer>the predecessor project Network Guard · {stamp} · this page reads saved scan state and
 cannot act on the network.</footer>
<script id="state" type="application/json">{payload}</script>
</body></html>"""


def register(registry) -> None:
    registry.register(
        "dashboard",
        skill_dashboard,
        aliases=[
            "guard dashboard", "network dashboard", "pane of glass",
            "overzicht",                                  # NL
            "tableau de bord",                            # FR
        ],
    )
