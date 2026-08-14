"""Data files must load as UTF-8 regardless of the OS locale.

This is the root cause of a bug that survived two rounds of fixing
because it was misdiagnosed as a console problem.

`open(path)` with no `encoding=` uses `locale.getpreferredencoding()`.
That is UTF-8 on Linux and cp1252 on a Western European Windows. The
KB YAML, the policy files and the JSON fixtures are all UTF-8 on disk
and contain em-dashes, so on Windows every one of those characters was
decoded as "â€"" *at load time*. The reports were then rendering
already-corrupt strings faithfully — nothing downstream could have
fixed it, and the console-encoding work did not touch it.

These tests simulate the Windows default so the failure is reproducible
on Linux CI, where it would otherwise be invisible.
"""

import builtins
import io
import json
import locale
import os

import pytest

import decoder
import fixes
import interpreter
import kb_lint
import policy
import triage

DATA_MODULES = [
    ("pattern KB", lambda: interpreter.load_rules()),
    ("chains", lambda: interpreter.load_chains()),
    ("triage profiles", lambda: triage.load_profiles()),
    ("policy", lambda: policy.load_policy()),
    ("error codes", lambda: decoder.load_codes()),
    ("fix map", lambda: fixes.load_fix_map()),
]


@pytest.fixture
def cp1252_default(monkeypatch):
    """Make bare open() behave the way it does on a Windows install.

    Any code path that forgot encoding="utf-8" will now raise or
    silently corrupt, exactly as it did on the real machine.
    """
    real_open = builtins.open

    def locale_open(file, mode="r", *args, **kwargs):
        if "b" not in mode and "encoding" not in kwargs:
            kwargs["encoding"] = "cp1252"
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", locale_open)
    monkeypatch.setattr(locale, "getpreferredencoding", lambda *a, **k: "cp1252")
    return locale_open


@pytest.mark.parametrize("name,loader", DATA_MODULES, ids=[n for n, _ in DATA_MODULES])
def test_data_loads_uncorrupted_under_a_cp1252_locale(name, loader, cp1252_default):
    """The regression: loaders must pin UTF-8, not inherit the locale."""
    loaded = loader()
    assert loaded, f"{name} loaded empty"

    text = json.dumps(loaded, default=str, ensure_ascii=False)
    # "â€" is the signature of UTF-8 bytes read through cp1252.
    assert "â€" not in text, f"{name} was decoded with the wrong codec"
    assert "Ã" not in text, f"{name} shows UTF-8-through-latin1 corruption"


def test_em_dashes_survive_the_round_trip(cp1252_default):
    """The specific character that broke on Windows."""
    codes = decoder.load_codes()
    blob = json.dumps(codes, ensure_ascii=False)
    assert "—" in blob, "the KB genuinely contains em-dashes; they must survive loading"
    assert "â€" not in blob


def test_kb_lint_runs_clean_under_a_cp1252_locale(cp1252_default):
    """Lint reads the KB as raw text too, for the threshold-comment check."""
    issues = kb_lint.lint()
    assert kb_lint.lint_exit_code(issues) == 0, [str(i) for i in issues]


def test_fixtures_load_under_a_cp1252_locale(cp1252_default):
    """Snapshot fixtures are read at runtime by demo and by the linter."""
    fixture_dir = os.path.join(os.path.dirname(__file__), "fixtures")
    for name in sorted(os.listdir(fixture_dir)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(fixture_dir, name), encoding="utf-8") as f:
            json.load(f)


def test_report_text_contains_no_mojibake_signature():
    """End-to-end guard on the symptom, not just the cause."""
    from interpreter import evaluate, resolve_chains
    from report import render_text
    from verdict import build_verdict

    path = os.path.join(os.path.dirname(__file__), "fixtures", "dying_disk.json")
    with open(path, encoding="utf-8") as f:
        snapshot = json.load(f)

    findings, worth, not_checked = evaluate(snapshot)
    chains, remaining = resolve_chains(findings)
    text = render_text(snapshot, remaining, worth, not_checked, chains=chains,
                       verdict=build_verdict(findings, not_checked, chains))

    assert "â€" not in text
    assert "Ã©" not in text
