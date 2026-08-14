#!/usr/bin/env bash
# Scheduled Network Guard patrol — the wrapper the systemd timer runs.
#
# Chapter two, item 1. Until 2026-07-27 the ONLY scheduled unit was
# huginn-triage, which runs `./ops triage` -- host diagnostics, importing
# nothing from census/guard/expose/patrol. Every Theme D detector (ARP
# spoofing, rogue DHCP, LLMNR/NBT-NS poisoning, ARP flood, DHCP starvation,
# persistent-anomaly escalation) therefore fired ONLY when the operator
# personally clicked Patrol. Theme D was complete as code and not as
# coverage. This wrapper is what closes that gap.
#
# Exit codes say what happened, and deliberately do not conflate two very
# different things:
#
#   0        the patrol RAN. It may have found nothing, or found plenty --
#            findings are not failures, and a red unit for "detected an
#            attack" would be indistinguishable from a red unit for "the
#            script is broken". That ambiguity is the exact confusion this
#            project exists to refuse.
#   non-zero the patrol COULD NOT RUN. systemctl shows red because the
#            guard is down, which is the only thing a status light here
#            can honestly mean.
#
# What it found is reported in the journal and recorded to the guard
# timeline, never inferred from the exit status.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "$HERE/../.." && pwd)"

JOURNAL="$PLATFORM/data/census/guard_events.json"

# Count journal lines before and after, then classify the NEW ones by
# severity. Reading the journal delta beats grepping the human summary for a
# phrase, which would break the first time the wording improved.
#
# **The delta alone is not the signal, and the first version of this script
# got that wrong.** `_is_change` (what earns a journal line) is deliberately
# WIDER than `should_alert` (what earns your attention): a phone leaving the
# network is a genuine change and correctly recorded, at severity `info`, and
# is equally correctly not worth waking anyone. A test run reported "11 change
# events" on a pass patrol itself called quiet -- eleven `lan_gone_*` lines.
# On a real LAN with devices sleeping and waking, that banner would fire every
# hour, which is how an operator learns to ignore the one line that matters.
# So `info` is counted as routine churn and reported quietly; anything above
# it -- or any severity this script does not recognise -- is surfaced.
before=0
[ -f "$JOURNAL" ] && before=$(wc -l < "$JOURNAL")

echo "[$(date -Is)] scheduled patrol starting"
"$PLATFORM/ops" patrol
rc=$?

if [ "$rc" -ne 0 ]; then
  echo "[$(date -Is)] PATROL FAILED TO RUN (exit $rc) — the guard is DOWN."
  echo "  This is not 'nothing found'. Nothing was checked."
  exit "$rc"
fi

after=0
[ -f "$JOURNAL" ] && after=$(wc -l < "$JOURNAL")
new=$(( after - before ))

if [ "$new" -lt 0 ]; then
  # The journal self-trims at MAX_JOURNAL_LINES (4000). A shrink means the
  # trim ran, so the arithmetic cannot be trusted. Say so; do not report 0.
  echo "[$(date -Is)] patrol ran; the journal was trimmed this pass, so the"
  echo "  new-event count is not computable. Read it directly: $PLATFORM/ops timeline"
  echo "[$(date -Is)] scheduled patrol done (exit 0)"
  exit 0
fi

if [ "$new" -eq 0 ]; then
  echo "[$(date -Is)] patrol quiet — nothing changed."
  echo "  A quiet patrol is not a guarantee of safety, only that nothing new"
  echo "  was seen in what could be checked."
  echo "[$(date -Is)] scheduled patrol done (exit 0)"
  exit 0
fi

# The classification rule lives in tools/patrol_summary.py, not here. It
# decides what is worth waking the operator for, which makes it a decision,
# and decisions in this project carry tests (tools/test_patrol_summary.py).
# It spent exactly one revision as a heredoc in this file and shipped two
# bugs in that time -- counting routine `info` churn as an incident, and
# printing "quiet" when it crashed -- neither catchable where it sat.
PY="$PLATFORM/.venv/bin/python"
[ -x "$PY" ] || PY="$(command -v python3)"
summary=$(tail -n "$new" "$JOURNAL" | "$PY" "$PLATFORM/tools/patrol_summary.py") \
  || summary=""

notable=$(printf '%s\n' "$summary" | sed -n 1p)
routine=$(printf '%s\n' "$summary" | sed -n 2p)
unreadable=$(printf '%s\n' "$summary" | sed -n 3p)
detail=$(printf '%s\n' "$summary" | tail -n +4)

# If the classifier did not produce a number, SAY SO. The first version
# defaulted a missing count to zero and printed "quiet" -- so a crashed
# classifier was indistinguishable from a clean LAN. That is the precise
# failure this project exists to refuse, and it appeared here within one
# revision of the script whose whole job is refusing it.
case "$notable" in
  ''|*[!0-9]*)
    echo "[$(date -Is)] PATROL RAN, BUT ITS $new NEW EVENT(S) COULD NOT BE CLASSIFIED."
    echo "  This is NOT an all-clear — the events exist and were not read."
    echo "  Read them directly:  $PLATFORM/ops timeline"
    echo "[$(date -Is)] scheduled patrol done (exit 0)"
    exit 0 ;;
esac

if [ "${unreadable:-0}" -gt 0 ]; then
  echo "  WARNING: $unreadable journal line(s) were malformed and not classified."
fi

if [ "$notable" -gt 0 ]; then
  echo "[$(date -Is)] PATROL ALERT: $notable finding(s) above routine churn."
  [ -n "$detail" ] && echo "$detail"
  echo "  Read them:  $PLATFORM/ops timeline"
  echo "  NOTE: delivery is not wired yet (chapter two, item 2). This pass is"
  echo "        RECORDED, not DELIVERED — nothing has notified anyone."
else
  echo "[$(date -Is)] patrol quiet — $routine routine device change(s) recorded,"
  echo "  nothing above info severity. Normal LAN churn; no attention needed."
fi

echo "[$(date -Is)] scheduled patrol done (exit 0)"
exit 0
