"""Classify the events one patrol pass wrote, for the scheduled wrapper.

Reads JSON-lines on stdin (the tail of `data/census/guard_events.json`) and
prints a short verdict for `packaging/systemd/huginn-patrol.sh` to log.

This exists as a file rather than a heredoc inside the shell script because
the rule it applies — **what is worth waking the operator for** — is a
decision, and decisions in this project carry tests. It lived in a bash
heredoc for exactly one revision, during which it shipped two bugs: it
counted routine `info` churn as an incident, and when it crashed the wrapper
printed "quiet". Neither was catchable where it sat.

Output contract (stable; the wrapper parses it):

    line 1   notable count
    line 2   routine count
    line 3   unreadable count
    line 4+  one indented line per notable event, up to --max

Exit status is 0 whenever classification SUCCEEDED, whatever it found —
findings are not failures. A non-zero exit means the classification itself
could not be done, which the wrapper reports as "not an all-clear".
"""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from domains.timeline import triage_events  # noqa: E402


def render(triage, max_detail=10):
    lines = [str(len(triage.notable)), str(triage.routine), str(triage.unreadable)]
    for event in triage.notable[:max_detail]:
        severity = str(event.get("severity", "?"))
        message = str(event.get("message", ""))
        lines.append("    [" + severity + "] " + message)
    extra = len(triage.notable) - max_detail
    if extra > 0:
        lines.append("    … and " + str(extra) + " more")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max", type=int, default=10,
                        help="how many notable events to spell out (default 10)")
    args = parser.parse_args(argv)
    print(render(triage_events(sys.stdin), args.max))
    return 0


if __name__ == "__main__":
    sys.exit(main())
