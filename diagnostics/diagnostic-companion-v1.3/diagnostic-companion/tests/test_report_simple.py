"""diag simple (spec §14.2) — accessible traffic-light card."""

import json
import os

from interpreter import evaluate
from report_simple import generate_support_code, render_simple

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def load_fixture(name):
    with open(os.path.join(FIXTURES_DIR, name)) as f:
        return json.load(f)


def test_render_simple_has_text_labels_not_colour_only():
    snapshot = load_fixture("dying_disk.json")
    findings, _worth_checking, not_checked = evaluate(snapshot)

    output = render_simple(snapshot, findings, not_checked)

    assert "[FAIL]" in output
    assert "Support code:" in output


def test_render_simple_never_contains_emoji():
    """§14.2: no emoji in terminal output, ever — this was violated once
    already (the Not-checked list used '⚪') and got fixed in report.py;
    this test exists so it can't regress silently in report_simple.py too."""
    snapshot = load_fixture("dying_disk.json")
    findings, _worth_checking, not_checked = evaluate(snapshot)

    output = render_simple(snapshot, findings, not_checked)

    assert all(ord(ch) < 0x2100 for ch in output), "found a non-ASCII/emoji-range character"


def test_support_code_is_deterministic_for_the_same_findings():
    snapshot = load_fixture("dying_disk.json")
    findings, _worth_checking, _not_checked = evaluate(snapshot)

    code_a = generate_support_code(snapshot, findings)
    code_b = generate_support_code(snapshot, findings)
    assert code_a == code_b
    assert code_a.startswith("DC-")


def test_not_checked_collector_shows_as_unknown_not_healthy():
    """dns_broken.json has logs collector skipped — must show [?], never [OK]."""
    snapshot = load_fixture("dns_broken.json")
    findings, _worth_checking, not_checked = evaluate(snapshot)

    output = render_simple(snapshot, findings, not_checked)
    lines = [l for l in output.splitlines() if "Recent system errors" in l]
    assert len(lines) == 1
    assert lines[0].startswith("[?]")
