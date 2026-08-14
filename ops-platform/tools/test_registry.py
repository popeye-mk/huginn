"""Tests for the native skill registry + discovery (A3 Phase 4).

Two things: the resolution contract (exact verb, alias, verb-first args, and
honest no-match so an unmatched line becomes a question), and the real proof —
`auto_discover` over the platform's OWN `skills/` directory registers the ops
verbs natively, through their `register(registry)` functions, with no fork.

Run: python3 tools/test_registry.py
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from runtime.registry import SkillRegistry, auto_discover  # noqa: E402

passed = 0


def check(cond, msg):
    global passed
    assert cond, msg
    passed += 1


def _fn(args, speaker=None):
    return f"ran({args})"


def _reg():
    r = SkillRegistry()
    r.register("census", _fn, aliases=["who is on the network", "lan census"])
    r.register("guard", _fn, aliases=["arp spoof"])
    return r


# --- resolution -----------------------------------------------------------

def test_exact_verb_and_alias():
    r = _reg()
    check(r.resolve("census") == ("census", ""), "exact verb")
    check(r.resolve("who is on the network") == ("census", ""), "exact alias")
    check(r.resolve("CENSUS") == ("census", ""), "case-insensitive")


def test_verb_first_carries_args():
    r = _reg()
    check(r.resolve("census passive") == ("census", "passive"), "first word is the verb, rest are args")
    check(r.resolve("lan census now") == ("census", "now"), "multi-word alias head + args")


def test_no_match_is_none_so_it_becomes_a_question():
    r = _reg()
    verb, text = r.resolve("what is the capital of France")
    check(verb is None and text == "what is the capital of France",
          "no verb matched → (None, original) so the caller can treat it as a question")


def test_punctuation_normalised_alias():
    r = _reg()
    check(r.resolve("arp-spoof?") == ("guard", ""), "punctuation-normalised alias still resolves")


def test_catalog_lists_verbs():
    cat = _reg().catalog()
    check("- census:" in cat and "- guard:" in cat, "catalog lists each verb with aliases")


# --- discovery over the platform's real skills ----------------------------

def test_auto_discover_registers_the_ops_verbs():
    r = SkillRegistry()
    n = auto_discover(r, str(ROOT / "skills"))
    check(n >= 10, f"discovered the ops verbs natively (got {n})")
    for verb in ("census", "guard", "timeline", "triage", "namewatch"):
        check(verb in r.skills, f"{verb} registered natively via its register()")


def test_disabled_modules_are_skipped():
    r_all = SkillRegistry(); auto_discover(r_all, str(ROOT / "skills"))
    r_lean = SkillRegistry(); auto_discover(r_lean, str(ROOT / "skills"), disabled_modules=["timeline"])
    check("timeline" in r_all.skills, "timeline registers when not disabled")
    check("timeline" not in r_lean.skills, "disabled module's verb is not registered")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print(f"{passed} tests passed")
