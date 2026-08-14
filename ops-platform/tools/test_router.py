"""Tests for the native request router (A3 Phase 4).

The router is the seam between the registry and the grounded answer path, so
these pin the three outcomes: a verb runs its skill (with args), a non-verb is
answered from the corpus, and an unanswerable line fails honestly — plus the
guarantee that a crashing skill becomes a failed command, not a crashed shell.

Run: python3 tools/test_router.py
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# `dispatch` now checks who owns the data directory, and claims an unclaimed
# one for the machine running it. Left pointed at the real folder, running
# this suite would stake a claim on the operator's live data under the test
# machine's hostname — and lock him out of his own tool on the next verb.
# It did exactly that once, before this line existed.
import os  # noqa: E402
import tempfile  # noqa: E402
os.environ["HUGINN_OWNER_FILE"] = os.path.join(tempfile.mkdtemp(), "OWNER.json")

from runtime.registry import SkillRegistry  # noqa: E402
from runtime.router import dispatch  # noqa: E402

passed = 0


def check(cond, msg):
    global passed
    assert cond, msg
    passed += 1


def _registry():
    r = SkillRegistry()
    r.register("census", lambda args, sp=None: f"CENSUS[{args}]", aliases=["lan census"])
    r.register("boom", lambda args, sp=None: (_ for _ in ()).throw(RuntimeError("x")))
    return r


def test_a_verb_runs_its_skill_with_args():
    res = dispatch(_registry(), "census passive")
    check(res.ok and res.message == "CENSUS[passive]", "verb runs, args passed through")


def test_a_non_verb_is_refused_honestly():
    """Answering was removed 2026-07-26: Huginn runs verbs, full stop."""
    res = dispatch(_registry(), "how do I set up a DHCP scope")
    check(res.ok is False, "a question is not a verb → not ok")
    check("do not answer general questions" in res.message,
          "she says plainly that answering is not her job")
    check("census" in res.message, "and lists the verbs that do exist")


def test_a_crashing_skill_is_a_failed_command_not_a_crash():
    res = dispatch(_registry(), "boom")
    check(res.ok is False and "boom failed" in res.message, "skill crash → failed command")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print(f"{passed} tests passed")
