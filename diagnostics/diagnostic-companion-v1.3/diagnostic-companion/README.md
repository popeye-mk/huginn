# Diagnostic Companion

A read-only health check for Windows and Linux machines that explains
what it found in plain language — and says plainly what it could not
check.

```
==================================================================
  ACTION REQUIRED
==================================================================
  One underlying problem explains several symptoms

  Disk space is critically low, alongside an unusually high volume
  of error-level log entries. A full disk is a common root cause
  of cascading service errors — fix the disk space first; the log
  errors likely resolve themselves once it does.

  Do this first: Clear space now (logs, temp files) or expand the
  volume before it fills.
==================================================================

Health score: 67/100   (4/4 checks ran)
```

Try that exact output on any machine, with no setup and no risk:

```bash
python3 cli.py demo dying-disk
```

## What makes it different

Most diagnostic tools dump data and leave you to interpret it. The two
ideas here are that a tool should **explain rather than dump**, and
should **never let silence look like health**.

- **Absence is never health.** A check that could not run is reported
  as "could not check", never omitted and never assumed fine. A run
  with gaps says so in its headline: *"No problems found in what could
  be checked — this is not a clean bill of health."*
- **Confidence is explicit.** Findings are `certain`, `likely` or
  `possible`. Only `certain` findings can drive a critical exit code,
  and `possible` ones can never headline a report.
- **Root-cause chains.** Related findings collapse into one story —
  "the disk is full, which is why the logs are full of errors" —
  instead of a flat list of symptoms. The narrative never softens the
  exit code automation reads.
- **The score is explainable by construction.** 100 minus a list of
  deductions, returned alongside the number, always carrying its
  coverage (`61 · 7/11 checked`).
- **It only reads.** No repair function, no writes, no network calls
  beyond DNS and ping checks. `diag fix` shows a plan and refuses to
  execute it.

## Quick start

```bash
git clone <this repo> && cd diagnostic-companion
pip install -r requirements.txt
python3 cli.py run
```

Or build a single self-contained binary that needs no Python:

```bash
python build.py --usb      # produces dist/diag (or diag.exe) + a USB kit
```

Verified on Linux (Ubuntu, glibc 2.39) and Windows 11 Pro 26200.
Windows collectors are tested against **real captured output** from a
live machine — see `tests/golden/`.

## Status

330 tests. Both operating systems verified against real hardware:
battery and Wi-Fi on a physical laptop, NVMe SMART on a real drive,
Windows collectors on a real Win11 install.

Not done, and honestly so: no code signing (SmartScreen warns on first
run), 20 knowledge-base rules is a seed set rather than coverage, the
fleet story reads a directory of snapshots rather than a real console,
and only an English locale has been tested.

## Every command

```bash
python3 cli.py run                    # full report
python3 cli.py run --format json
python3 cli.py run --anon             # hostname/public IPs/SSID/log text redacted — spec §4.3, §5
python3 cli.py simple                 # end-user traffic-light card — spec §14.2
python3 cli.py baseline               # save current state as "known good"
python3 cli.py run --diff             # what changed since baseline — spec §6.1
python3 cli.py menu                   # guided menu, safe to show a client
python3 cli.py demo dying-disk        # zero setup, zero risk — spec §14.5
python3 cli.py demo healthy

python3 cli.py why slow               # symptom-driven triage — spec §7
python3 cli.py why no-internet
python3 cli.py run --format html -o report.html  # one-file report — spec §14.4
python3 cli.py policy check           # compliance vs policy/kmo-default.yaml — spec §9
python3 cli.py fix                    # whitelisted remediation, dry-run — spec §14.3
python3 cli.py verify snapshot.json   # tamper-evident check — spec §14.7
python3 cli.py fleet snapshots/        # correlate across machines — spec §8, §14.6
python3 cli.py decode 0x80070005      # Windows error-code decoder — spec §10
python3 cli.py kb lint                # knowledge-base discipline — spec §12.3
```

Exit codes: `0` healthy, `1` warnings, `2` critical (only `certain`-confidence
findings can produce `2` — spec §3.5, §16). A root-cause chain narrative
never softens this: exit codes are always computed from the flat,
pre-chain finding list.

## Desktop launchers

Everything click-related lives in `launchers/` — see its README. Two
entry points at the project root:

```bash
./install-launcher.sh            # Linux: install
./install-launcher.sh --remove   # Linux: uninstall
install-launcher.bat             # Windows
```

Adds an applications-menu entry and a desktop icon that open the guided
menu. Prefers `dist/diag` if it has been built, otherwise falls back to
running from source, so it is useful before packaging.

Two details this gets right that hand-written `.desktop` files usually
miss: `Terminal=true` (without it a console program launches with
nowhere to draw and appears to do nothing at all), and marking the
desktop copy executable *and* trusted via `gio` — GNOME and Nautilus
refuse to run an untrusted `.desktop`, which is why such shortcuts
commonly appear as a plain text file.

Absolute paths are fine here because it points at a fixed location on
this machine. That is exactly why the same approach is *not* used for
the USB kit, where the mount point changes.

### Windows

`install-launcher.bat` creates Desktop and Start Menu shortcuts.

Three details that a hand-made shortcut usually gets wrong, and this
does not: the Desktop path is *asked for* rather than assumed (it is
localised, and OneDrive Backup redirects it entirely — hardcoding
`%USERPROFILE%\Desktop` produces a shortcut nobody ever sees);
`WorkingDirectory` is pinned to the program's folder so reports land
beside the executable rather than wherever Explorer happened to be; and
the icon falls back to the one PyInstaller embeds in `diag.exe` when no
separate `.ico` is present.

### Icons

`tools/make_icons.py` draws the `.ico` and `.png` programmatically with
Pillow rather than rasterising the SVG — no cairosvg/Inkscape
dependency, and small sizes get *simpler geometry* rather than a
downscaled 256px image, which turns to mush below 32px.

## Testing the Windows collectors on real Windows

See `VM_TESTING.md` for the full step-by-step (Python install, what to
run, what is expected to break and in what order).

`collectors/windows/*.py` have never run against an actual Windows
machine — see `tools/capture_windows_golden.py`'s docstring. If you
have a Win11 box or a Windows Server to test on:

```powershell
pip install -r requirements.txt
python cli.py run --format text          # the real end-to-end experience
python tools\capture_windows_golden.py   # per-collector raw PS output + parse() result
```

The capture script needs no admin rights and changes nothing — it runs
the same read-only queries `diag run` would. It writes
`windows_capture_output.txt` next to itself; send that file (or the
`diag run` output) back so the parsing bugs it turns up can get fixed
and turned into real `tests/golden/` fixtures (spec §19).

## Test it

```bash
python3 -m pytest -q
```

330 tests, all fixture-, golden- or subprocess-based (no live hardware assumptions
baked into the suite itself):

- **Interpreter tests** — healthy snapshot has no findings; a dying-disk
  snapshot fires the critical disk rule and *not* the superseded warning
  rule; a `possible`-confidence finding never appears as a headline; a
  skipped collector shows up in "Not checked" and never produces a
  finding; SMART reallocated-sector data fires as critical.
- **Chain tests** — the dying-disk chain fires and consumes both member
  findings from the display; partial evidence (only one of two `when`
  ids present) never fires a chain; a `possible`-confidence finding is
  structurally ineligible for chain membership.
- **`diag simple` tests** — text labels present (no colour-only
  signalling), no emoji in the output, a skipped collector renders `[?]`
  never `[OK]`, support codes are deterministic.
- **Diff tests** — disk-space and error-count deltas detected between
  two real fixtures; new/resolved finding ids computed correctly;
  no-change case stays quiet.
- **Redaction tests** — a fixture seeded with every known sensitive
  pattern (hostname, public IP, private IP, SSID, MAC, email, home-dir
  path) comes out clean under `--anon`; a completeness test asserts
  every active collector has a registered redaction rule, and
  `redact_snapshot()` raises rather than silently passing through an
  unregistered one.
- **Linux optional-collector tests** — battery health is computed from
  either `energy_*` (watt-hours) or `charge_*` (amp-hours) firmware,
  because both are standard and reading only the first returned null
  health on a real Acer laptop, making both battery rules structurally
  unfireable with nothing in the report saying so. Wi-Fi values from
  `/proc/net/wireless` (`"70."`) are converted to numbers rather than
  travelling as strings.
- **Optional-collector tests** — battery/Wi-Fi/SMART all degrade to a
  clean `Skip` on this sandbox (no battery, no wireless adapter,
  unprivileged), proving the "unavailable → say so" path against real
  system state, not mocks.
- **Golden Windows tests** — the shipped parsers run against verbatim
  output from a real Windows 11 machine (`tests/golden/`): uptime from
  the PS 5.1 date format, a single volume collapsed to a bare object,
  the DNS hashtable surviving serialisation, CRLF collapsed out of log
  messages, and a real `0x80073D02` update failure decoded out of log
  text while the DCOM GUID in the same logs is correctly ignored.
- **Windows-collector tests** — `parse()` functions checked against
  realistic canned PowerShell JSON; `collect()` proven to `Skip` cleanly
  when PowerShell isn't present; `error_count` proven not to saturate at
  the entry-sample size; a non-ASCII (Dutch) event-log message survives
  parsing intact.
- **CLI demo tests** — run `diag demo` as a subprocess exactly as a user
  would, check exit codes and JSON-on-stdout hygiene.
- **HTML report tests** — the report reaches nothing outside itself (no
  CDN, no `http://`); a hostile hostname and an injected log line both
  come out escaped rather than as markup; the "Not checked" section is
  present in every rendering.
- **Triage tests** — selected and excluded collectors always partition
  the full set (nothing can vanish from a narrowed run); every
  collector id and weighted rule id in `triage.yaml` is checked to
  actually exist; weighting reorders findings without changing the set.
- **Policy tests** — a skipped collector yields `unknown`, never
  `pass`; an unknown can never produce a clean exit code; the rendered
  report states out loud that unknowns are not compliance.
- **Fix/verify tests** — a KB entry naming a non-whitelisted command
  raises; no whitelisted command contains an interpolation placeholder;
  only `risk: low` is suggestible; hashes are stable across key
  ordering and tampering is detected.
- **KB lint tests** — the *shipped* KB must pass its own linter (a bad
  rule fails the build), plus detection of duplicate ids, dangling and
  circular `supersedes`, chain members naming unknown rules, and triage
  profiles pointing at collectors or rules that don't exist.
- **Decoder tests** — every input form a user might type resolves to
  one entry; an unknown code returns `None` rather than a guess, and
  says so without implying "harmless".
- **Fleet tests** — an asset whose collector didn't run is excluded
  from *both* the numerator and denominator and named explicitly; two
  of two assets is not treated as a pattern; the health score always
  equals 100 minus its own listed deductions.
- **Missing-vs-null tests** — a rule matching `equals: null` fires on a
  reported null and stays silent on an absent field.
- **Data-encoding tests** — every loader is exercised with `open()`
  monkeypatched to cp1252, reproducing the Windows default on Linux CI.
  This is the only reason the mojibake bug is now catchable without a
  Windows machine: it asserts that KB text survives loading intact,
  rather than that the console printed it nicely.

## What's actually implemented

- `schema.py` — the versioned per-collector envelope (§4.3).
- `collectors/base.py` — timeout/error/skip wrapper plus
  `is_elevated()`/`require_privilege()` (§3.1/§3.3/§3.4).
- `collectors/core/{system,network,disk,logs}.py` — real Linux collectors.
- `collectors/optional/{battery,wifi,smart}.py` — real Linux collectors,
  auto-skip when not applicable or not privileged (§4.2).
- `collectors/windows/{system,disk,network,logs}.py` — PowerShell/CIM
  equivalents, **unverified against a real Windows machine** (see Known
  gaps). `cli.py` dispatches to them on `platform.system() == "windows"`.
- `pattern_kb/entries.yaml` — generalised `{path, op, value}` matching,
  `supersedes`-based precedence (§6).
- `pattern_kb/chains.yaml` + `interpreter.resolve_chains()` — root-cause
  chains that collapse related findings into one story for display only;
  exit codes always read the pre-chain data (§14.1, §16).
- `diffing.py` — baseline value/finding comparison (§6.1).
- `redact.py` + `docs/DATA_INVENTORY.md` — `--anon` export: hostname
  and Wi-Fi SSID always masked (stable hash), public IPs masked/private
  IPs kept, log free-text best-effort scrubbed. Every collector's
  redaction decision is registered and completeness-tested (§4.3, §5).
- **All project data is read with an explicit `encoding="utf-8"`.**
  Bare `open()` uses the OS locale codepage — UTF-8 on Linux, cp1252 on
  a Western European Windows — so the KB's em-dashes were being
  corrupted at load time on Windows and every report faithfully
  rendered the damage. This is enforced by `tests/test_data_encoding.py`
  rather than by remembering.
- `portable.py` — USB operation: reports are written beside the
  executable (`sys.executable`, not the temp extraction directory) and
  named `HOSTNAME_YYYY-MM-DD_HHMM.html`, so one stick collects one
  report per machine instead of each overwriting the last. Falls back
  to the home directory on a write-protected stick and says so.
  Hostnames are sanitised before reaching a path (§13).
- `elevate.py` — drive health is the only check needing elevation, so
  the menu offers it as a separate, explained option rather than
  escalating as part of a normal run. A tool that asks for
  administrator rights on someone else's machine without saying why is
  indistinguishable from one you should not run. Uses `pkexec` in
  preference to `sudo` (a desktop icon may have no terminal to type a
  password into) and UAC on Windows, and treats a cancelled prompt as a
  legitimate answer rather than an error. The read-only guarantee holds
  when elevated: elevation buys access to disk counters, nothing that
  writes (§3.1, §3.2).
- `menu.py` — the front door when the packaged binary is
  double-clicked, since argparse usage text would otherwise flash past
  and close. Written to be read by the client whose machine it is:
  plain language, the read-only guarantee stated up front, and `fix`
  deliberately unreachable — a menu shown to someone else is the wrong
  place to expose the one command that could change anything. Every
  option executes a real command line, so the menu cannot grow a second
  diagnosis path.
- `console.py` — §14.2 bans emoji from terminal output because consoles
  mangle them; the same applies to every non-ASCII character, and the
  codebase broke its own rule with em-dashes in KB text (an em-dash came
  out as `â€"` on the first Windows run). stdout is reconfigured to
  UTF-8 where possible, and anything the stream still cannot encode is
  transliterated to meaningful ASCII (`—` to ` - `, `→` to `->`) rather
  than mangled or fatal. Also why report output uses `-o FILE` rather
  than shell redirection: `>` on Windows writes through the console
  codepage and can silently truncate a file that looks like it
  succeeded.
- `verdict.py` — the one plain-language sentence a reader should take
  away, shared by the terminal and HTML reports so they can never
  disagree. Enforces the rule that matters most: a verdict may never
  say "healthy" over partial coverage. "Nothing wrong was found" and
  "this machine is fine" are different claims (§3.4, §15.11).
- `report.py` / `report_simple.py` — full terminal report and the
  end-user traffic-light card, both text-labelled, zero emoji (§14.2).
- `report_html.py` — `--format html`: one self-contained file, inline
  CSS/JS, no network. Opens with the plain-language verdict, then
  health score and coverage, then findings with expandable raw
  evidence, chain stories, decoded error codes, baseline diff and a
  "what was not checked" section. Light/dark aware, responsive, and
  carries a print stylesheet that assumes no colour survives — so
  severity is legible on a black-and-white printout. Every collected
  value is HTML-escaped (§13, §14.4).
- `triage.py` + `pattern_kb/triage.yaml` — `diag why <symptom>` runs
  only the collectors relevant to a complaint and weights the rules
  most likely to explain it. Collectors the profile skipped are merged
  into "Not checked" as `not_run`, so a narrowed run can never read as
  a clean bill of health (§7, §3.4). Unknown symptom falls back to a
  full run.
- `policy.py` + `policy/kmo-default.yaml` — `diag policy check`
  evaluates a snapshot against declarative rules with **three**
  outcomes: pass, fail, and `unknown` for rules whose collector didn't
  run. `unknown` is never folded into pass and never exits 0 (§9).
- `fixes.py` — `diag fix` dry-run remediation from a code-reviewed
  command whitelist (a KB entry names a *key*, never a command string,
  so a KB edit cannot introduce a new command); only `risk: low` is
  ever suggestible. Also `diag verify` + SHA-256 snapshot stamping, so
  a snapshot attached to a ticket is evidence (§14.3, §14.7, §13).
- `kb_lint.py` — `diag kb lint`: structural completeness, duplicate and
  circular `supersedes`, chain/triage referential integrity, threshold
  comments, rule provenance, and fixture coverage. The check that would
  have caught v4's triage weights pointing at rules that never existed
  (§12.3). Runs in CI.
- `decoder.py` + `pattern_kb/error_codes.yaml` — `diag decode
  0x80070005`: 10 Windows Update failure codes and 8 BSOD stop codes to
  plain language plus a next step. Needs no snapshot — the entry point
  is a technician holding a code a user read out over the phone (§10).
  `scan_snapshot()` also lifts codes out of collected log text
  automatically, so a run surfaces "Error codes found in the logs"
  without anyone having to notice the hex string. It ignores GUIDs and
  unknown codes rather than guessing at them.
- `collectors/windows/_dates.py` — `ConvertTo-Json` serialises DateTime
  as `/Date(epoch_ms)/` on PowerShell 5.1 and ISO 8601 on 7.x. Both are
  parsed; anything unrecognised returns None so a wrong timestamp can
  never reach a report.
- `fleet.py` — `diag fleet`: correlates identical finding ids across
  snapshots and leads with the environment-level conclusion ("4 of 5
  checked assets report this — open ONE ticket"). Assets whose relevant
  collector didn't run are excluded from both numbers and named. Also
  the explainable health score: 100 minus a list of deductions that is
  returned with the number, always carrying its coverage (§8, §14.6).
- `pattern_kb/entries.yaml` — 16 rules, each with provenance (§12.1)
  and a comment on every threshold saying where the number came from.
- `cli.py` — `run [--diff] [--format]`, `why`, `policy check`, `fix`,
  `verify`, `fleet`, `decode`, `kb lint`, `baseline`, `simple`, `demo`.

## Known gaps (intentional — see Next Steps doc)

- **Windows is verified on exactly one machine and one locale.** All
  four collectors were captured and confirmed against Windows 11 Pro
  26200 / PowerShell 5.1 / en-GB, unelevated. Not yet covered: an
  elevated run, PowerShell 7 (whose `ConvertTo-Json` emits ISO dates —
  handled in code, untested against a real box), a non-English UI
  culture (spec §19 asks for Dutch/French specifically), multiple
  volumes, and Windows Server. Optional collectors (battery/Wi-Fi/SMART)
  are still Linux-only.
- **Timeout is thread-based, not subprocess-based** — see
  `collectors/base.py`'s docstring. Spec's real fix (§3.3) is v1 work.
- **Windows optional collectors are written but unverified.**
  battery/Wi-Fi/SMART now have Windows implementations using
  locale-independent CIM classes (not `netsh` text, which is
  translated, and not `powercfg /batteryreport`, which writes a file
  and would break the read-only guarantee). The test VM had no battery,
  no wireless adapter and a virtual disk with no reliability counters,
  so only their Skip paths have actually run.
- **Support codes aren't checksummed or decodable yet.** `diag simple`
  prints a code (§14.2) but there's no `diag decode` lookup and no
  misread-detection — see `report_simple.py`'s docstring.
- **Baseline is single-machine, not fleet-scale.** Stored at
  `~/.diagnostic-companion/baseline.json`; the Ops Console's per-asset
  timeline (§18) is the real version and is v2 work.
- **Log-entry redaction is best-effort, not guaranteed-complete.** Free
  text can contain anything; only IPv4, MAC, email, and home-directory
  patterns are scrubbed today. Stated plainly in `docs/DATA_INVENTORY.md`
  rather than implied to be exhaustive.
- **`docs/DATA_INVENTORY.md` only covers collectors that exist.** Every
  future optional collector (AAD/Intune, certificates, USB, printers,
  ...) needs a row there and a `SECTION_REDACTORS` entry before it can
  ship in `--anon` output — several of those fields will be more
  sensitive than anything collected today and deserve real scrutiny.
- **`diag fix --apply` is deliberately not implemented.** The dry-run
  plan is complete and correct; executing it needs per-fix
  confirmation, a post-fix collector re-run to *prove* the fix worked,
  and a rollback story for non-reversible commands. Half of that is
  worse than none, so `--apply` prints the plan and refuses (exit 1).
- **Triage profiles have no `ask` step yet.** Spec §7 allows at most
  two binary questions that measurably prune the collector set
  ("Wired or Wi-Fi?"). The profile format has room for it; the
  interactive layer isn't built.
- **Policy is single-machine.** `diag policy check` evaluates one
  snapshot. The HTML compliance tab (§9) is not built; `diag fleet`
  now provides the multi-asset half, but the two are not joined up.
- **KB feedback loop and governance tooling are not built.** §12.2's
  hit-rate stats, auto-demotion below 50%, `diag kb review`, signed KB
  bundles and `pattern_kb/local/` overrides are all absent. Provenance
  and quarantine (§12.1) and `kb lint` (§12.3) are in; the rest is not.
- **Fleet is file-based, not a console.** `diag fleet` reads a
  directory of snapshots. There is no asset registry, no timeline, and
  no trend arrow — §14.6's "days since baseline" needs per-asset
  history that only the Ops Console (§18) provides.
- **The decoder is a seed set, not coverage.** 16 codes. It is
  structured so adding more is a YAML edit, but an unknown code is
  common and the tool says so rather than guessing.
- **No packaging, signing, GDPR module, or KB governance.**
  All by design for this phase — see `Diagnostic_Companion_Next_Steps.md`
  §1 for why those are deferred rather than forgotten.

## A live data point from building this

Running `diag run` inside the sandbox this was built in surfaces a real
`dns_resolution_failing` finding — `/proc/net/route` has no default
route and DNS genuinely doesn't resolve here, because the sandbox's
network is restricted rather than the machine being broken. It also
correctly reports `battery`/`wifi`/`smart` as skipped rather than
healthy, because this VM genuinely has none of those. That's "absence
is never health" working as designed against an environment the tool
was never told is unusual. On a normal laptop, expect battery/Wi-Fi
data to actually populate — and on the dying-disk demo, expect a single
root-cause story instead of two separate findings.

A third bug, caught by building the fleet fixtures: `no_default_gateway`
matches `gateway == null` and fired on every healthy machine, because
the path resolver returned `None` both for "collector reported null"
and "collector never reported this field". Those are different facts —
the first means there is genuinely no gateway, the second means no
data — and §3.4 says only the first may produce a finding. The
resolver now returns a `MISSING` sentinel, rules skip it, and
`policy check` reports it as `unknown` rather than a pass. That one
would have shipped as a false positive on every machine.

Two earlier bugs the tests caught. First, the HTML report
attached raw-evidence blocks by parsing the collector name out of the
finding id — which works for `disk_free_critical` and silently fails
for `high_error_log_volume` (there is no collector called "high").
Findings now carry an explicit `collector` field derived from the
rule's own match path. Chasing that turned up the worse one: in
`interpreter.evaluate()`, the rendering loop read `match["path"]` from
the *matching* loop's leftover loop variable, so every finding was
labelled with whichever rule the matcher happened to end on — all of
them came out as `wifi`. Both are now covered by tests that assert the
collector attribution per fixture, not just that a finding fired.

An earlier bug this round of work caught and fixed: `report.py`'s
"Not checked" section originally used "⚪" to mark unchecked items —
an emoji character, which spec §14.2 explicitly forbids in terminal
output (Windows consoles and legacy SSH terminals mangle them). Fixed
to a plain `[?]` text label, and a regression test
(`test_render_simple_never_contains_emoji`) now guards against it
happening again in `report_simple.py` too.

## Licence

MIT — see [LICENSE](LICENSE). Use it, learn from it, fork it. No warranty.
