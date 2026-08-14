# Golden fixtures (spec §19)

`win11_26200_ps51.json` is **verbatim PowerShell output from a real
Windows 11 Pro machine** — build 26200, PowerShell 5.1.26100, en-GB UI
culture, unelevated — captured with `tools/capture_windows_golden.py`
on 2026-07-20.

Do not hand-edit it. It is evidence, not a fixture someone invented,
and its value is precisely that nobody chose what it contains.
`tests/test_golden_windows.py` runs the shipped parsers against it.

## What this capture settled

- **`ConvertTo-Json` serialises DateTime as `/Date(epoch_ms)/` on
  PowerShell 5.1.** This is why `windows/system.py` shipped without
  uptime for so long — the format was genuinely ambiguous without a
  machine to check. `collectors/windows/_dates.py` now handles both
  this and the ISO form PowerShell 7 emits.
- **A single fixed disk collapses to a bare JSON object**, not a
  one-element array. The parser's `isinstance(obj, list)` guard is
  load-bearing, not defensive padding.
- **A PowerShell hashtable round-trips as a JSON object**, so the DNS
  results map survives as expected.
- **Event log messages contain CRLF mid-sentence**, producing run-on
  whitespace when naively flattened.
- **Log free text embeds error codes** (`0x80073D02` here) alongside
  GUIDs that must *not* be mistaken for codes.

## Adding another capture

Run `tools/capture_windows_golden.py` on the machine, save the raw
output per collector into a new file named for the OS build and
PowerShell version, and add a test module for it. Different Windows
versions and locales are separate evidence and deserve separate files —
especially a non-English UI culture, which is the case spec §19 calls
out and which this capture does not cover.
