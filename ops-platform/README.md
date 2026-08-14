# Huginn

**A network watchdog built around one unusual idea: radical honesty about
what it did and did not check.**

Huginn watches a single network — a home or a small office — and tells you
what changed: a device you do not recognise joining, something impersonating
your router, a fake copy of your Wi-Fi, a machine talking to a known-bad
address. It is named for one of Odin's ravens: it flies out, sees, and comes
back to report.

Two things set it apart from the usual network monitor:

- **It never acts on your network.** No blocking, no disconnecting, no
  changing settings — it detects and *proposes*, and you decide. This is
  enforced by a test that parses the code, not by good intentions.
- **It never lets "not checked" look like "all clear".** Every finding
  carries how much it could actually see, and anything it could not check is
  reported as a gap in plain words. A grey "unknown" is never dressed up as
  a green "fine". Most monitoring tools quietly do the opposite.

It runs on the Python **standard library alone** — no dependencies, no
account, nothing that phones home — and the same code runs on Linux,
Windows, and macOS.

---

## Quick start

**Windows:** open `packaging\windows\` and double-click `Install-Huginn.bat`.
It finds Python (installs it if needed), sets up an hourly background check,
and puts a **Huginn** icon on your desktop. Full walkthrough:
[`docs/WINDOWS-QUICKSTART.md`](docs/WINDOWS-QUICKSTART.md).

**Linux / macOS:**

```bash
bash packaging/linux/install.sh      # Python check, icon, hourly check
# or just run it directly:
./huginn                             # open the console in your browser
./ops patrol                         # run one full check from the terminal
```

Then open the console at **http://127.0.0.1:8790** (local only — nothing on
your network or the internet can reach it) and read the four status boxes.

The complete guide, written for non-technical readers and with a glossary,
is [`docs/MANUAL.md`](docs/MANUAL.md).

---

## What it checks

| | |
| - | - |
| **Who is here** | every device on the network, and anything new since last time |
| **Is anyone lying** | signs of a device impersonating the router or handing out addresses (ARP spoofing, rogue DHCP) — the basis of most local eavesdropping |
| **The air** | Wi-Fi transmitters faking your network name ("evil twin") |
| **Open doors** | devices exposing risky ports |
| **Name poisoning** | anything answering to hostnames that should not exist (Responder-style attacks) |
| **Outbound** | connections to addresses on public known-bad lists |
| **This machine** | host health, exposure, and whether a backup could actually be restored (proven by booting it) |

Every finding comes with **how sure it is** (certain / likely / possible)
and **a suggested next step you** carry out.

---

## The design rules it holds to

These are the reason the project exists, and they are enforced by the test
suite, not just described:

- **Absence is never health.** A check that could not run must never look
  like a check that passed. Every finding carries `checked / total`
  coverage; nothing defaults to "fine".
- **Detect and propose, never act.** Blocking is deliberately unbuilt. The
  one component that could lock you out of your own network is the one that
  does not exist.
- **Zero dependencies.** Standard-library Python only, verified by a test.
  A tool used mid-incident must not need the internet just to start.
- **One place for OS differences.** Every "if Windows" lives in
  `platform_support/`, so "runs on both" cannot rot into "runs on the one I
  tested". A portability test fakes each OS in turn to prove it.
- **Local only, by default.** The console binds `127.0.0.1` and has no
  login — safe *only* because of that binding, and it shows its live address
  so the assumption stays visible.

---

## How it is built

Five layers, dependencies pointing downward only (enforced by
`tools/test_architecture.py`):

```
contracts/         pure data types; depend on nothing
platform_support/  the only module that branches on operating system
engines/           external-tool wrappers; the only place that shells out
domains/           pure logic — facts in, findings out; no side effects
agents/            coordinate domains and engines
skills/            one command ("verb") each; thin — parse, delegate, format
runtime/           the command registry, router, and local web server
```

Full detail in [`ARCHITECTURE.md`](ARCHITECTURE.md).

## Running the tests

```bash
python3 tools/test_architecture.py            # the structural rules
for f in tools/test_*.py; do python3 "$f"; done   # the full battery
```

45 suites, 800-plus individual checks, green on Linux, Windows and macOS.

**Note on optional companions.** Two engines (`netdiag` for network
diagnostics, Diagnostic Companion for host checks) are *separate* projects
Huginn calls when they are present beside it. Cloned on its own, Huginn runs
fine without them — those engines report themselves unavailable rather than
failing, and the two tests that cross-check their knowledge bases skip
honestly and say so.

---

## Status and honesty

This is a working tool, run and verified on real Linux and Windows machines,
with recovery-from-backup demonstrated on both. It is also a personal-scale
project: it has watched a small number of networks for a short time, not a
fleet for years. A couple of platform-specific paths (a Hyper-V console
reader, a Windows file-ACL lockdown) are written from documentation but not
yet confirmed against the real thing, and say so in their own comments.

If something here does not do what the docs claim, that is a bug worth
reporting — this project treats a false "all clear" as the worst possible
outcome, in its documentation as much as its code.

---

## License

MIT — see [`LICENSE`](LICENSE).
