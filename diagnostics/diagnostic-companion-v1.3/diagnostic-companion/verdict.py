"""Plain-language verdict (spec §14.2, §15.11).

Every report currently opens with data. A person opening it wants one
sentence first: is this machine fine, and if not, what is the one thing
that matters. This module produces that sentence, and it is deliberately
the only place in the codebase allowed to summarise — so the wording
stays consistent between the terminal, the HTML report and `diag simple`
instead of drifting into three slightly different claims.

The honesty rules from §3.4 apply harder here than anywhere else,
because a headline is what people quote. Specifically: a verdict can
never say "healthy" when coverage is partial. "Nothing wrong was found"
and "this machine is fine" are different claims, and only the first one
is ever true after a run that skipped collectors.
"""

VERDICT_OK = "ok"
VERDICT_WARNING = "warning"
VERDICT_CRITICAL = "critical"


def build_verdict(findings, not_checked, chains=None):
    """Returns {level, headline, detail, action, coverage_caveat}."""
    chains = chains or []
    criticals = [f for f in findings if f["severity"] == "critical"]
    warnings = [f for f in findings if f["severity"] == "warning"]

    # Coverage first: it qualifies every other statement below.
    caveat = None
    if not_checked:
        names = ", ".join(sorted(cid for cid, _s, _r in not_checked))
        caveat = (
            f"{len(not_checked)} check(s) could not run ({names}). "
            "Nothing is claimed about them either way."
        )

    if chains:
        root = chains[0]
        return {
            "level": VERDICT_CRITICAL if criticals else VERDICT_WARNING,
            "headline": "One underlying problem explains several symptoms",
            "detail": root["story"],
            "action": _first_action(findings),
            "coverage_caveat": caveat,
        }

    if criticals:
        first = criticals[0]
        more = len(criticals) - 1
        headline = first["finding"]
        if more:
            headline += f" (and {more} other critical issue{'s' if more > 1 else ''})"
        return {
            "level": VERDICT_CRITICAL,
            "headline": headline,
            "detail": "This needs attention now — it is unlikely to resolve on its own.",
            "action": first.get("next_step"),
            "coverage_caveat": caveat,
        }

    if warnings:
        first = warnings[0]
        more = len(warnings) - 1
        headline = first["finding"]
        if more:
            headline += f" (and {more} other warning{'s' if more > 1 else ''})"
        return {
            "level": VERDICT_WARNING,
            "headline": headline,
            "detail": "Not urgent, but worth handling before it becomes urgent.",
            "action": first.get("next_step"),
            "coverage_caveat": caveat,
        }

    # The careful case. "No problems found" is a statement about the
    # tool's coverage, not a clean bill of health for the machine.
    if not_checked:
        return {
            "level": VERDICT_OK,
            "headline": "No problems found in what could be checked",
            "detail": (
                "Some checks did not run, so this is not a clean bill of health — "
                "it is the absence of findings in the parts that were examined."
            ),
            "action": None,
            "coverage_caveat": caveat,
        }

    return {
        "level": VERDICT_OK,
        "headline": "No problems found",
        "detail": "Every check ran and none of them found anything wrong.",
        "action": None,
        "coverage_caveat": None,
    }


def _first_action(findings):
    for finding in findings:
        if finding.get("next_step"):
            return finding["next_step"]
    return None
