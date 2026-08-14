# Diagnostic Companion — Next Steps to Realization

Companion to `Diagnostic_Companion_Spec_v5.md`. The spec answers *what*
to build; this answers *what to do next*.

**Status as of 2026-07-20 (Windows verified end to end).** The original version of this document was
written before any code existed and argued for a v0 walking skeleton
beneath the spec's own v1. That happened, and then some. This revision
replaces the pre-code planning with an honest account of what is built,
what is verified, and what genuinely remains.

---

## 1. Where the project actually is

Built, tested, and green on Linux (135 tests):

| Area | Spec | State |
|---|---|---|
| Collect → interpret → report | §4, §6 | Real, Linux collectors live |
| Schema envelope, "absence is never health" | §3.4, §4.3 | Enforced mechanically |
| Confidence tiers, exit codes | §3.5, §16 | Done, chains never soften exit codes |
| Root-cause chains | §14.1 | Done |
| Baseline / diff | §6.1 | Done, single-machine |
| `--anon` redaction + data inventory | §5, §4.3 | Done, completeness-tested |
| `diag simple` | §14.2 | Done |
| `diag demo` | §14.5 | Done |
| One-file HTML report | §14.4 | Done, all values escaped |
| `diag why <symptom>` | §7 | Done, no interactive `ask` step |
| `diag policy check` | §9 | Done, single-machine |
| `diag fix` dry-run | §14.3 | Plan only; `--apply` deliberately refused |
| Tamper-evident snapshots | §14.7 | Done |
| `diag fleet` correlation + health score | §8, §14.6 | Done, file-based |
| Windows error-code decoder | §10 | 16 codes, extensible by YAML |
| KB provenance + quarantine | §12.1 | Done |
| `diag kb lint` | §12.3 | Done, runs in CI |

Not built, by deliberate sequencing: packaging and code signing (§13.1,
§20), the GDPR/audit module (§5's formal half), KB feedback stats and
signed KB distribution (§12.2, §12.4), i18n (§7's four languages), the
Ops Console and ticket push (§11, §18), `diag watch`.

---

## 2. Windows is verified (2026-07-20)

All four Windows collectors ran on a real Windows 11 Pro VM (build
26200, PowerShell 5.1.26100, en-GB, unelevated) and **all four parsed
correctly on the first attempt**, including `network.py`, which was
flagged as highest-risk for chaining five cmdlets.

The raw output is committed as `tests/golden/win11_26200_ps51.json` and
13 golden tests now run the shipped parsers against it on every commit.

What the capture changed:

- **Uptime is implemented.** It was deliberately absent because
  `ConvertTo-Json` serialises DateTime differently across PowerShell
  versions and guessing was the wrong call. The capture settled it
  (`/Date(epoch_ms)/` on 5.1); `collectors/windows/_dates.py` handles
  that and the ISO form 7.x emits.
- **Log timestamps are readable.** They were being printed as
  `/Date(1784538433261)/`.
- **Log messages have CRLF collapsed** — real messages break
  mid-sentence.
- **The decoder now scans log text.** The capture contained a genuine
  `0x80073D02` update failure, which the tool now decodes automatically
  and explains. It ignores the DCOM GUID sitting in the same logs.
- **Four "failing" tests were a test bug, not a code bug** — they
  asserted collectors Skip when PowerShell is absent, which was only
  true because the build machine was Linux. Now simulated rather than
  assumed.

### Verified on Windows 11 Pro 26200

Final run: 199 tests pass on Windows, `kb lint` clean, all seven
collectors dispatch correctly (four run, three skip honestly), uptime
parses, log timestamps render, the decoder lifts a real error code out
of log text, and both the terminal and HTML reports render correctly
with no character corruption.

### Still unverified on Windows

One machine, one locale, one PowerShell version. Not yet covered:

- An **elevated** run. `is_elevated()` on Windows has only ever
  returned False, so the SMART collector has never actually executed —
  only its privilege refusal has.
- **Battery and Wi-Fi on real hardware.** A VM structurally cannot test
  these; their Windows implementations have only ever taken the Skip
  path.
- **PowerShell 7** — the ISO date path is implemented but untested
  against a real box
- **A non-English UI culture** — spec §19 asks for Dutch/French, and
  this capture was en-GB. This is where the UTF-8 encoding work pays
  off or turns out to be insufficient.
- **Multiple volumes** — the capture had one disk, so the array branch
  of `disk.py` is still only covered by canned fixtures
- **Windows Server**, and the optional collectors (battery/Wi-Fi/SMART),
  which remain Linux-only

---

## 3. Ranked next steps

1. **A second Windows capture on a non-English locale** (§19). The
   single highest-value remaining test, because it is where the
   forced-UTF-8 work either holds or doesn't, and the failure mode is
   invisible on an English machine. A Dutch or French Windows VM, one
   run of the capture script.

2. **Windows optional collectors.** Battery, Wi-Fi and SMART are
   Linux-only. The schema is OS-agnostic and the auto-skip machinery
   already works; this is collector work, not architecture work.

3. **Packaging, tested against Defender** (§13.1, §20). The spec is
   explicit that this is the actual showstopper and that reputation
   builds over calendar time. Test PyInstaller vs. Nuitka vs. zipapp
   against a real Defender install *before* committing to one. This is
   the highest-risk unstarted item, because it can fail in ways no
   amount of code quality prevents.

4. **The interactive `ask` step in triage** (§7). Two binary questions
   that measurably prune the collector set. The profile format already
   has room for it. Small, visible, and it makes `diag why` feel like a
   conversation rather than a flag.

5. **HTML compliance tab** (§9). `policy check` and the HTML report both
   exist; joining them is the "one page a manager reads" deliverable and
   is mostly plumbing.

6. **KB feedback loop** (§12.2). Hit-rate stats, auto-demotion below
   50% after 10 firings, `diag kb review`. Worth building specifically
   because "how do you know your tool is right?" is the question an
   interviewer will ask, and "I measure it" beats "it's a good rule set".

Deliberately still deferred: fleet console, `diag fix --apply`, i18n,
signed KB distribution, AAD/Intune/M365 collectors. Each needs either
infrastructure that doesn't exist yet or an external dependency
(a tenant, a cert, a ticket system) that isn't secured.

---

## 3a. The encoding bug, and why it took three attempts

Worth recording in full, because the shape of the mistake is more
instructive than the fix.

**Symptom:** an em-dash from the KB rendered as `â€"` on Windows.

**First diagnosis (wrong):** a console problem. §14.2 already bans
emoji from terminal output because consoles mangle them, so this looked
like the same class of bug. Built `console.py` to force UTF-8 on stdout
and transliterate anything unencodable.

**Second state (actively worse):** forcing UTF-8 made
`sys.stdout.encoding` report `utf-8`, so the transliteration check
concluded everything was encodable and switched itself off — while
cmd.exe carried on rendering those bytes as cp1252. The fix disabled
the safety net built to catch the thing it was fixing. It also broke
three CLI tests: the child now emitted UTF-8, the test harness decoded
the pipe as cp1252, and `UnicodeDecodeError` in subprocess's *reader
thread* meant `proc.stdout` came back as `None` rather than failing
loudly.

**Actual cause:** `open(path)` with no `encoding=` uses
`locale.getpreferredencoding()` — UTF-8 on Linux, cp1252 on Western
European Windows. The KB YAML is UTF-8 on disk, so every em-dash was
corrupted *at load time*. Both renderers were faithfully printing
already-broken strings. No amount of console work could have fixed it.

**What made it findable:** the HTML report. `-o` writes UTF-8
explicitly, so when the mojibake appeared in the *file* too, the
corruption had to be upstream of rendering. A terminal-only symptom
kept pointing at the terminal.

**What makes it not recur:** `tests/test_data_encoding.py`
monkeypatches `open()` to cp1252, reproducing the Windows default on
Linux CI. Verified by reintroducing one bare `open()` — the suite
fails. Before this, the bug was structurally invisible without a
Windows machine.

The general lesson, worth applying beyond this project: a symptom that
only appears on one platform is not automatically a platform-specific
bug. It can be a platform-specific *default* exposing a bug that was
always there.

---

## 4. What testing has actually been worth

Worth recording, because it is the honest answer to "why so many tests
for a portfolio project": the test suite has caught four real bugs that
would otherwise have shipped, and three of them were silent.

- An emoji in the terminal report's "Not checked" section — forbidden by
  §14.2 because Windows consoles mangle it.
- The HTML report attaching raw evidence by parsing the collector name
  out of the rule id, which works for `disk_free_critical` and silently
  fails for `high_error_log_volume`.
- A leaked loop variable in `interpreter.evaluate()` that labelled every
  finding with whichever rule the matcher happened to end on. Every
  finding in every report had the wrong source collector.
- A path resolver that could not distinguish "collector reported null"
  from "collector never reported this field", making
  `no_default_gateway` fire on every healthy machine.
- Data files read with the OS locale codepage, corrupting every
  non-ASCII character in the knowledge base on Windows (§3a).
- Four Windows "test failures" that were a test bug: they asserted
  collectors Skip when PowerShell is absent, which was only ever true
  because the build machine was Linux.

The last two are the interesting ones. Both were invisible in the
terminal output — the findings were correct, only their attribution was
wrong — and both were found by writing a test for a *new* feature that
happened to depend on the old code being right. Neither would have been
caught by using the tool.

---

## 5. Open risks worth tracking

- **Windows verification is now the critical path**, and it is the one
  thing that cannot be done from a Linux box.
- **Defender/SmartScreen reputation takes calendar time**, independent of
  feature progress. If a signed binary matters for a demo, the clock
  starts at cert purchase, not at packaging.
- **Locale testing** (§19) needs an actual Dutch/French Windows install.
  Cheap to spin up now, expensive to discover missing before a demo.
- **KB growth without the feedback loop.** 16 rules is small enough to
  hold in your head. `kb lint` enforces structure and provenance, but
  nothing yet measures whether a rule is *right*. That gap widens with
  every rule added, and §12.2 exists precisely because it ends badly.
- **Scope creep remains the biggest risk to this spec.** The original
  version of this document warned that v5's ambition outpaces solo build
  time. That is less true than it was — but the remaining items are the
  expensive ones (packaging, signing, console, i18n), and it is worth
  re-reading §1's honest-moat list before starting any of them.

---

## 6. Definition of done for "interview-ready"

Original checklist, updated:

- [x] `diag demo dying-disk` runs on a clean checkout with zero setup
- [x] One root-cause chain fires and reads as a *story*, not a rule dump
- [x] `diag simple` and the HTML report both render correctly
- [x] At least one "Not checked" line appears in a demo run
- [ ] The same demo runs on Windows — **blocked on §2**
- [x] You can explain why this beats osquery/RMM in under 30 seconds

The last unchecked box is the same one as §2. Everything else is done.
