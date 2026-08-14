# Testing diagnostic-companion on a Windows 11 VM

Fast path. Should take about 15 minutes, most of it the Python install.

---

## 1. Install Python (the only prerequisite)

In the VM, open **PowerShell** and run:

```powershell
winget install Python.Python.3.12
```

Then **close and reopen PowerShell** (so PATH updates) and check:

```powershell
python --version
```

If `winget` isn't available, download from python.org instead and tick
**"Add python.exe to PATH"** during install — that checkbox is the one
thing people miss, and skipping it makes every later step fail.

PowerShell itself is already on Win11. Nothing else to install.

---

## 2. Get the code in

Copy `diagnostic-companion-vm-ready.zip` into the VM (shared folder,
drag-and-drop, or a USB passthrough) and extract it.

```powershell
cd $HOME\Downloads\diagnostic-companion
pip install -r requirements.txt
```

Only two dependencies: `pyyaml` and `pytest`.

---

## 3. Confirm the suite passes on Windows

```powershell
python -m pytest -q
```

Expect **141 passed**. If anything fails here, it's a Windows/Python
portability problem in code that has nothing to do with the collectors —
worth knowing before the interesting part.

```powershell
python cli.py kb lint
```

Expect "Knowledge base is clean."

---

## 4. The actual test

```powershell
python cli.py run --format text
```

This is the first time the Windows collectors have ever run on Windows.
Expect problems here — that is the point of the exercise, not a failure
of it.

Then the capture, which is what I actually need back:

```powershell
python tools\capture_windows_golden.py
```

No admin rights needed, changes nothing, read-only queries only. It
prints and writes `windows_capture_output.txt` containing, per collector:
the PowerShell command, the raw output, and either the parsed result or
the full traceback.

It also records PowerShell version, UI culture and console encoding up
front — those three explain most parse failures before you even read
the parse.

---

## 5. Worth trying while you're in there

```powershell
python cli.py run --format html > report.html
start report.html

python cli.py why slow
python cli.py simple
python cli.py demo dying-disk
python cli.py decode 0x80070005
```

The HTML report opening correctly in Edge is a real check — it's meant
to be a single self-contained file that survives being emailed around.

**Run as Administrator once too.** Elevation changes which collectors
can run, and `is_elevated()` on Windows has never been exercised:

```powershell
python cli.py run --format text
```

---

## 6. Send back

- `windows_capture_output.txt`
- Output of `python cli.py run --format text` (both elevated and not)
- Any pytest failures

That's enough to turn the captures into real `tests/golden/` fixtures
and fix whatever the parsers got wrong.

---

## What I expect to break

Ranked, so you know whether what you're seeing is expected:

1. **`network.py`** — chains five cmdlets (`Get-NetIPConfiguration`,
   `Get-DnsClientServerAddress`, `Resolve-DnsName`, `Test-Connection`
   twice). `ConvertTo-Json` collapses single-item arrays in ways that
   are easy to get subtly wrong. Highest risk by a distance.
2. **`logs.py`** — `Get-WinEvent` filter behaviour and the shape of the
   `Entries` array.
3. **`system.py`** — should be fine, but **uptime will be missing**.
   That's deliberate: `LastBootUpTime` comes back in two different
   formats depending on PowerShell version and I refused to guess.
   Your capture is what lets me implement it correctly.
4. **`disk.py`** — lowest risk. `Win32_LogicalDisk DriveType=3` is
   stable, well-documented territory.

Two bugs I already fixed ahead of this session, so you shouldn't hit them:

- **Output encoding** was left to the system codepage, which would
  produce mojibake or a hard `UnicodeDecodeError` on any non-English
  Windows. Now forced to UTF-8 on both sides.
- **`error_count`** was `len(entries)` with entries capped at 20, so it
  silently maxed out at 20 on Windows — meaning the KB rule that fires
  above 100 errors could never fire on Windows at all. Now counts the
  full 24-hour window and returns the sample separately.
