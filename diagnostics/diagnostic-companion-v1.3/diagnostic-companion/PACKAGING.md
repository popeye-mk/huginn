# Packaging (spec §20, §13.1)

## Build it

```bash
pip install pyinstaller
python3 build.py
```

Produces a single self-contained executable at `dist/diag`
(`dist\diag.exe` on Windows). No Python required on the target machine.

PyInstaller does not cross-compile: **a Windows .exe must be built on
Windows.** Build inside the Win11 VM, in the folder the ISO copies to.

```
python build.py            # onefile — for distribution
python build.py --onedir   # fallback, see "If Defender objects"
python build.py --check    # re-verify an existing build
```

## Why the build verifies itself

`build.py` does not consider a build successful because a file appeared.
It runs six checks against the binary, and one of them is the reason the
script exists at all:

**If the knowledge base fails to bundle, the tool still starts, still
runs every command, and reports every machine as healthy.** No rules
means no matches means no findings means "no problems found". A
packaging mistake would be indistinguishable from a clean machine —
the exact inversion of §3.4 that the whole project is built to avoid.

So the build asserts that the binary can load its own rules and
reproduce a *known finding from a known fixture*. `cli.py` also calls
`resources.assert_data_files_present()` at startup and refuses to run
without its knowledge base, rather than running and lying.

This was not hypothetical. The first build passed four of six checks:
`diag demo` and `diag kb lint` both crashed because `tests/fixtures`
was not bundled. `demo` is a shipped feature (§14.5), so those fixtures
are now shipped data.

## Verified builds (2026-07-20)

| Platform | Python | Size | Checks | Notes |
|---|---|---|---|---|
| Linux (Ubuntu, glibc 2.39, kernel 7.0) | 3.12.3 | 9.1 MB | 6/6 | built in a venv |
| Windows 11 Pro 26200 | 3.12.10 | 8.4 MB | 6/6 | Defender did not flag it |

Two separate artefacts from one source tree — PyInstaller does not
cross-compile, so each OS builds its own. Build in a virtualenv on
Linux; newer distributions block installing PyInstaller into the system
Python, and keeping it out of there is the right instinct anyway.

## Result on Windows 11 Pro 26200 (2026-07-20)

Built in a Win11 Pro VM, Python 3.12.10, PyInstaller 6.21.0.

- **Build succeeded**, 8.4 MB single file
- **All six verification checks passed**
- **Windows Defender did not flag it** — no quarantine on write, no
  real-time protection alert during the build
- Real-time protection was active and default; this was not a machine
  with AV disabled

That is the good case, and it is worth being precise about what it does
*not* establish: SmartScreen reputation is a separate mechanism from
Defender's malware scanning. A file downloaded from the internet
carries a mark-of-the-web that this locally-built binary does not, so a
distributed copy may still trigger a SmartScreen warning on first run
even though Defender is content with the contents.

## Making a USB stick

```bash
python build.py --usb
```

Assembles `dist/usb-kit/` — the binary, `README.txt`, and the launcher
matching the platform you built on (`RUN-DIAGNOSTIC.bat` on Windows,
`run-diagnostic.sh` on Linux). Only one launcher ships, because the
binary is platform-specific anyway and the other would just invite
someone to try it and get a confusing error.

Copy the contents to a stick.

**Windows has a real double-click story; Linux does not.** Most Linux
file managers open a `.sh` in an editor rather than running it, and
`.desktop` launchers cannot resolve paths relative to themselves, which
breaks on removable media whose mount point changes. `run-diagnostic.sh`
is therefore written to be run from a terminal, and it handles the two
things that actually go wrong there: it resolves its own directory
(following symlinks) so reports land beside the binary regardless of
where it was invoked from, and it restores the executable bit, which
FAT32 and exFAT do not store. If the stick is mounted `noexec` — some
managed systems enforce that for removable media — it says so and tells
the user to copy the folder to their home directory.

The workflow it supports: plug in, double-click, check the machine,
walk away with a report. Reports are written **beside the executable**
and named per machine and timestamp, so a stick accumulates one file
per machine rather than each visit overwriting the last. On a
write-protected stick they fall back to the user's home directory and
the program says so on screen.

Worth putting both build forms on the stick if you will meet managed
machines: some environments block executables that unpack themselves
to `%TEMP%`, which is what the onefile build does. `--onedir` does not.

Note for client-facing use: an unsigned binary will trigger a
SmartScreen warning the first time on a machine that has not seen it.
`usb/README.txt` explains it, but it is better said out loud before it
appears than explained afterwards.

## If Defender objects

This is the genuine unknown, and per §13.1 the one thing that can fail
for reasons no amount of code quality prevents. Record what actually
happens:

| Question | Why it matters |
|---|---|
| Does Defender flag `diag.exe` on write? | Real-time protection quarantining on build is the worst case |
| Does a full scan flag it? | Slower signal, same problem |
| Does SmartScreen warn on first run? | Expected without signing; the question is the exact wording |
| Does `--onedir` behave differently? | onefile self-extracts to `%TEMP%` on every run, which is itself a heuristic trigger |

Things already done to reduce the surface, all reversible if they turn
out not to matter:

- **UPX is disabled.** Executable compression correlates strongly with
  malware packing in AV heuristics. The size saving is not worth it.
- **Unused heavy modules are excluded** (tkinter, numpy, pytest,
  setuptools). Smaller bundle, less for a scanner to consider.
- **Version metadata is embedded** on Windows (`version_info.txt`,
  generated by `build.py`) so the binary identifies itself rather than
  appearing anonymous.

If onefile is flagged and onedir is not, ship onedir. The distribution
story is slightly worse (a folder instead of a file) and the honesty
story is unchanged, which is the right trade.

## Code signing

Not done, and it is a purchasing decision rather than a technical one.
The spec (§13.1) is explicit that the certificate should be obtained
*before* it is needed, because SmartScreen reputation accrues over
calendar time and downloads — not on the day you decide you want it.

- An OV certificate is roughly $200-400/year
- Reputation builds over weeks of downloads, so the clock starts at
  first signed release, not at purchase
- Unsigned, expect a SmartScreen warning on every first run on a new
  machine, which for a *diagnostic* tool is a particularly bad look:
  the tool asking to be trusted is the one Windows is warning about

The honest fallback for a portfolio project is to leave it unsigned,
document the warning, and demonstrate awareness of why it matters. That
is a defensible position in an interview. Silently ignoring it is not.

## What is deliberately not in the binary

- **The test suite.** Bundling pytest into a diagnostic tool shipped to
  end users is wrong; the tests protect the repository, not the user.
- **`tests/golden/`.** Real captured Windows output, used to verify
  parsers at development time.
- **The spec and Next Steps documents.**

`diag kb lint`'s fixture-coverage check is skipped in a frozen binary
rather than failing, because it asks a question about the repository's
health that a packaged binary cannot meaningfully answer.
