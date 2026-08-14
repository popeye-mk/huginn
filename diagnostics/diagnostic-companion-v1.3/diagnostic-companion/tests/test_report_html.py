"""HTML report tests (spec §14.4, §13).

The load-bearing test here is the escaping one: the snapshot contains
log lines, hostnames and SSIDs, all of which are just text that some
other process chose. If any of it reaches the page as markup, the
report becomes an injection vector the moment it's emailed around.
"""

import json
import os

import pytest

from interpreter import evaluate, resolve_chains
from report_html import render_html

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load(name):
    with open(os.path.join(FIXTURES, name)) as f:
        return json.load(f)


def render(name):
    snapshot = load(name)
    findings, worth, not_checked = evaluate(snapshot)
    chains, remaining = resolve_chains(findings)
    return render_html(snapshot, remaining, worth, not_checked, chains=chains)


def test_html_is_self_contained():
    """No external requests — it must work from a USB stick, offline."""
    html = render("dying_disk.json")
    assert html.startswith("<!doctype html>")
    assert "</html>" in html
    for external in ("<script src=", "<link rel=\"stylesheet\"", "http://", "https://"):
        assert external not in html, f"HTML report reaches outside itself: {external}"


def test_collected_values_are_escaped():
    """A hostile hostname must never become markup (§13)."""
    snapshot = load("healthy.json")
    snapshot["hostname"] = "<img src=x onerror=alert(1)>"
    findings, worth, not_checked = evaluate(snapshot)
    html = render_html(snapshot, findings, worth, not_checked)

    assert "<img src=x" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_log_text_in_evidence_is_escaped():
    """Log free-text is the most attacker-influenceable field there is."""
    snapshot = load("dying_disk.json")
    snapshot["sections"]["logs"]["data"]["injected"] = "</pre><script>alert(1)</script>"
    findings, worth, not_checked = evaluate(snapshot)
    html = render_html(snapshot, findings, worth, not_checked)

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_not_checked_section_always_present():
    """§3.4 — a report that silently omits coverage reads as health.

    Asserted case-insensitively on the phrase rather than on exact
    heading copy: the requirement is that coverage is always stated,
    not that it is worded one particular way.
    """
    for fixture in ("healthy.json", "dying_disk.json", "smart_failing.json"):
        assert "not checked" in render(fixture).lower()


def test_healthy_snapshot_says_so_explicitly():
    """A clean run must state plainly that nothing was found — and scope
    the claim to what actually ran."""
    html = render("healthy.json").lower()
    assert "nothing wrong was found" in html or "no problems found" in html
    assert "checks that ran" in html or "could be checked" in html


def test_chain_renders_as_one_story():
    html = render("dying_disk.json")
    assert "ROOT CAUSE" in html
    assert "Explains:" in html


def test_severity_is_never_colour_only():
    """Every badge carries a text label as well as a colour (§14.2)."""
    html = render("dying_disk.json")
    assert "FAIL" in html or "ROOT CAUSE" in html
    assert "sev-" in html  # colour classes exist...
    # ...but the label text is what carries the meaning
    assert ">FAIL<" in html or ">ROOT CAUSE<" in html
