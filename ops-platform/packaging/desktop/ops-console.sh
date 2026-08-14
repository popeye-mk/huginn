#!/usr/bin/env bash
# The little console the desktop icon opens.
#
# A loop over the platform's verbs, so testing does not require
# remembering paths or verbs -- click the icon, press a number.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "$HERE/../.." && pwd)"

while true; do
  clear
  echo
  echo "  ANORA OPS -- test console"
  echo "  ========================================"
  echo
  echo "   1) triage      full picture, correlated"
  echo "   2) security    security-focused triage"
  echo "   3) threat      connections vs threat feeds"
  echo "   4) devices     fleet overview"
  echo "   5) backup      backup verification status"
  echo "   6) netcheck    network diagnostics"
  echo "   7) diagnose    host diagnostics"
  echo "   8) history     ask the findings memory"
  echo
  echo "   t) run the full test suite"
  echo "   q) quit"
  echo
  read -rp "  choice: " c
  echo
  case "$c" in
    1) "$PLATFORM/ops" triage ;;
    2) "$PLATFORM/ops" security ;;
    3) "$PLATFORM/ops" threat ;;
    4) "$PLATFORM/ops" devices ;;
    5) "$PLATFORM/ops" backup ;;
    6) "$PLATFORM/ops" netcheck ;;
    7) "$PLATFORM/ops" diagnose ;;
    8) read -rp "  ask about: " q; "$PLATFORM/ops" history $q ;;
    t) for s in "$PLATFORM"/tools/test_*.py "$PLATFORM"/tools/smoke_*.py; do
         python3 "$s" >/dev/null 2>&1 \
           && echo "  ok    $(basename "$s")" \
           || echo "  FAIL  $(basename "$s")"
       done ;;
    q) exit 0 ;;
    *) echo "  ?" ;;
  esac
  echo
  read -rp "  [enter to continue] " _
done
