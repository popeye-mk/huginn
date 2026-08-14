# Huginn — the manual

Huginn is a quiet watchdog for one network — your home or small office. It
watches who and what is connected, notices when something changes, and tells
you. It is named for one of Odin's ravens: it flies out, sees, and comes
back to report.

Two things about it are worth knowing before anything else, because they
shape everything:

- **It never changes your network.** It will not disconnect a device, block
  anyone, or alter a setting. It watches and it tells you; *you* decide what
  to do. This is on purpose (a watchdog that starts biting the family gets
  locked outside, and then it guards nothing).
- **It never guesses.** If it could not check something, it says so in plain
  words instead of pretending everything is fine. A grey "not checked" is a
  different thing from a green "all clear", and it will never dress one up as
  the other.

New to all this? Skim **"What Huginn watches for"** just below, then follow
**"Getting started"** to install it. The **Glossary** at the very end
explains every technical word in plain English — if a term trips you up,
jump there.

> **On Windows and just want it running?** There is a one-page,
> clicks-only start in **`docs/WINDOWS-QUICKSTART.md`**. This manual is the
> complete version and covers every system; the quickstart is the short
> path for a Windows PC.

---

## Which part to read

| If you are… | Read |
| - | - |
| brand new, and just want it running and readable | **Getting started** + **Part 1**. That is enough. |
| the person looking after this network day to day | **Part 2** as well — the commands and the routines |
| the person who has to keep the software itself working | **Part 3** — how it is built, tested and rebuilt |

You do **not** need to be technical to use Huginn. Getting started and Part 1
assume nothing. Part 2 assumes you can open a terminal and are willing to.
Part 3 is for whoever maintains the code.

---

## What Huginn watches for

In plain terms, these are the everyday dangers on a small network, and what
Huginn does about each. You do not need to understand the mechanics — the
point is that these are real things that happen, and Huginn is looking for
them so you do not have to.

- **A device you do not recognise joins your network.** A neighbour guessing
  your Wi-Fi password, a stranger's phone, something that should not be
  there. Huginn keeps a list of what belongs, and flags anything new.
- **Something pretends to be your router.** Your router is the box that
  connects you to the internet; every device trusts it. A common attack is
  for one device to impersonate the router so it can quietly read everyone's
  traffic. Huginn watches for the tell-tale signs.
- **A fake copy of your Wi-Fi ("evil twin").** An attacker sets up a network
  with the same name as yours, hoping a device connects to theirs by
  mistake and hands over a password. Huginn learns which Wi-Fi transmitters
  are really yours and flags impostors.
- **A device leaves a dangerous door open.** Some settings let a device be
  reached from outside in risky ways. Huginn checks for the well-known bad
  ones and tells you which device and how to close it.
- **A device on your network is talking to a known-bad address on the
  internet.** Often the sign of malware. Huginn compares outbound
  connections against public lists of known-bad addresses.

Everything Huginn finds comes with **how sure it is** (certain, likely, or
possible) and **what you could do about it**. It never cries wolf as fact
when it only has a suspicion.

---
---

# Getting started — installing Huginn

Huginn needs **Python** (a free, common piece of software many programs use)
and nothing else. There is no account to make and nothing that phones home.
The installers below make sure Python is present, put a **Huginn icon on
your desktop**, and start the hourly check running. Two optional extras
(`nmap` and `numpy`) make it a little faster and smarter; it works fine
without them and tells you when they are missing.

## On Windows

1. Copy the `ops-platform` folder onto the computer (from the disc, a USB
   stick, or a download).
2. Open the `packaging\windows` folder inside it.
3. **Double-click `Install-Huginn.bat`.** If it offers to install Python or
   the optional extras, say yes. It does **not** need administrator rights.
4. When it finishes, double-click the new **Huginn** icon on your Desktop.
   The console opens in your web browser.

That is the whole install. From then on Huginn checks the network every
hour on its own, and catches up on any check it missed while the computer
was switched off.

## On Linux

1. Open a terminal in the `ops-platform` folder.
2. Type this and press Enter:

   ```bash
   bash packaging/linux/install.sh
   ```

3. Answer its questions (install Python if it is missing, the optional
   extras, the hourly check). It only asks for your password (`sudo`) if you
   let it install a system package, and it tells you before it does.
4. Find **Huginn** in your applications menu and on the Desktop. If the
   desktop icon says it is untrusted, right-click it and choose *Allow
   Launching*.

## What the installer actually did

Nothing mysterious, and nothing you cannot undo:

- copied Huginn into your own user folder;
- made a desktop and menu shortcut that opens the console;
- set up a background check that runs every hour — no service running with
  special powers, nothing new listening on the network.

**To remove it later:** delete the shortcut and the installed folder. On
Windows, also delete the "Huginn patrol" task in Task Scheduler. On Linux,
run `./packaging/systemd/install-timer.sh patrol --remove`.

---
---

# Part 1 — Reading the console

Click the **Huginn** desktop icon (or open `http://127.0.0.1:8790` in a web
browser on the same computer). It only works from that computer, on purpose —
nothing on your network or the internet can reach it.

## The four boxes across the top

These four boxes are the whole answer to *"is my network OK right now?"*.
Each shows a coloured dot, like a traffic light:

| Dot | Means |
| - | - |
| 🟢 **green** | this was checked, and it is fine |
| 🟠 **amber** | this was checked, and it needs your attention |
| ⚪ **grey (hollow)** | this **could not be checked at all** |

**Grey is not "sort of green."** It means Huginn does not know. A watchdog
that showed green when it was actually blindfolded would be worse than
useless, so Huginn never does that. If a dot is grey, the box tells you what
it could not see.

### Box 1 — "Last patrol": is the watchdog awake?

- **Green** ("14 minutes ago") — a check ran recently. The small print says
  what it found; "nothing above info" means a quiet, clean check.
- **Amber** ("9 hours ago") — nothing has run for a while. Usually this just
  means the computer was switched off, which is normal. If it has been on
  all day, the hourly check may have stopped (see *If Huginn itself seems
  broken* in Part 2).
- **Grey** ("never recorded") — no check has ever run yet. Click **Check
  now** to run one.

### Box 2 — "If something happens": would you actually be told?

- **Green** — at least one alert method can reach you when you are away from
  the computer (your phone, or email).
- **Amber** ("desktop only") — an alert would pop up on this screen and
  nowhere else. Fine while you are sitting here, but that is not really the
  point of an alert.
- **Amber** ("nobody is told") — findings are being recorded, but no alert
  goes anywhere. Open **⚙ Setup → Who gets told** to fix it.

The small print says *"nothing is proven until a test alert arrives."*
Turning an alert on is not the same as it working — use **Save & send test
alert** and check the message actually reaches you.

### Box 3 — "Witnesses": how many computers are watching?

Huginn's network checks rely on one computer's memory of its neighbours. A
clever attacker's whole trick is to rewrite that memory. A **second**
computer running Huginn keeps its own separate memory — and if the two
disagree, that disagreement is strong evidence something is wrong.

- **Amber** ("1 — this machine only") — only this computer is watching. This
  is not a fault; it is simply a limit. With one witness there is nothing to
  cross-check against. It stays amber until a second computer on the same
  network also runs Huginn.
- **Green** ("2 reporting") — two or more computers are comparing notes.
- **Grey** ("none reporting") — no current report exists.

### Box 4 — "Confirmed as yours": anything unaccounted for?

This box counts devices on your network **and** Wi-Fi transmitters together,
and "confirmed" has a strict meaning:

> **Confirmed means a human said "that one is mine."** Not that Huginn has
> seen it before. Huginn remembers everything it meets — that is how it
> spots newcomers — but a device simply being *tolerated* for a month does
> not make it *identified*.

So a fresh install will say something like **"11 unconfirmed"** even when
nothing is wrong. That number is a **to-do list, not an alarm.** Work
through it once (see *Confirming what is yours* in Part 2) and it drops to
zero. After that, a new "unconfirmed" genuinely means something arrived.

## The rest of the screen

- **Check now** — runs a full check straightaway. Takes a minute or two.
  This is the button to press if you are worried.
- **Watch / What changed / This machine / Act** — drawers of less-used
  commands. You can ignore all of them for normal use.
- **⚙ Setup** — three tabs: who gets alerted, what is yours, and how loud.
- The **box at the bottom** lets you type a command by name. Anything in
  Part 2 can be typed there.

## What to do when a box turns amber

1. Click **Check now** and read what comes back. Under each finding it tells
   you, in plain words, what to do.
2. Each finding is labelled **info**, **warning**, or **critical**. Info is
   just a note. Warning wants a look. Critical wants you now.
3. Each finding also says how sure it is — **certain**, **likely**, or
   **possible**. Huginn says "this looks like X" rather than "this is X"
   when it cannot prove it, and it means the difference literally.

## What Huginn will never do

It will not block, disconnect, or change anything on your network. Every
finding ends with a suggestion for **you** to carry out. That is a
deliberate choice, explained in Part 3.

---
---

# Part 2 — Using it day to day

Everything in Part 1 is clickable. This part is for when you want more, and
it uses the **terminal** (the typed-command window). If you are comfortable
opening one, read on; if not, the console alone covers most needs.

## Two ways to run it

Open a terminal in Huginn's folder. A "command" here is one of the named
checks below — Huginn calls them **verbs**. The two entry points are the
same on every system; only the spelling differs:

| | Linux / macOS | Windows |
| - | - | - |
| open the console | `./huginn` | `python -m runtime.app` |
| run one verb | `./ops <name>` | `python tools\ops.py <name>` |

The rest of this part writes commands in the short **`./ops <name>`** form
to save space. On Windows, read every `./ops <name>` as
`python tools\ops.py <name>` — they do exactly the same thing. (Everyday
users never need this: the desktop icon opens the console, and the console
has a buttons-and-typing box for the same verbs.)

## The five you will actually use

```
./ops patrol      # the full sweep: who is here, is anyone lying, what is open
./ops census      # just: what is connected to the network right now
./ops wifi        # just: which Wi-Fi transmitters are broadcasting
./ops timeline    # what has changed over the past week
./ops digest      # a short weekly summary
```

Everything else is for a specific question or a specific incident.

## All the verbs

### Watching the network

| Verb | Answers | Cannot see |
| - | - | - |
| `patrol` | all of the below in one pass, and alerts you | — |
| `census` | what is connected right now, and what is new | devices that have gone quiet |
| `guard` | is anything impersonating the router or handing out addresses | the raw traffic — it reasons from symptoms |
| `expose` | which devices leave risky doors (ports) open | anything behind a barrier it cannot reach |
| `wifi` | is a transmitter faking your Wi-Fi (an "evil twin") | transmitters out of range |
| `namewatch` | is anything answering to names that should not exist | attackers that stay silent |
| `corroborate` | do the watching computers agree about the network | anything, if only one computer is watching |

### Seeing what changed

| Verb | Answers |
| - | - |
| `dashboard` | one web page: every device, its name, its open ports |
| `timeline` | what moved on the network over the past week |
| `digest` | a short weekly summary, good for emailing yourself |
| `history` | have I seen this finding before, and how often |
| `devices` | an overview across several computers |

### Checking this computer itself

| Verb | Answers |
| - | - |
| `triage` | the headline: run every check and tie it into one story |
| `diagnose` | is this computer healthy |
| `netcheck` | when the internet is bad, whose fault is it |
| `security` | what this computer exposes |
| `backup` | could I actually restore from backup — proven by booting it |
| `threat` | is anything here talking to a known-bad address |

### Doing something about it

| Verb | Does |
| - | - |
| `harden` | asks the first question: *would an attack even work here?* |
| `mitigate` | prints the exact fix commands for each finding — **you** run them |
| `capture` | freezes the current evidence to a file, for later |
| `label` | gives a device a name you will recognise |
| `ack` | marks one open port as known-and-fine, so only surprises stay loud. `ack <ip> <port>`; undo with `ack unack <ip> <port>`. Changes nothing on the network |
| `admin` | shows who gets alerted; `admin test` proves it works |
| `adopt` | takes over a data folder that belonged to another computer |

Verbs also understand Dutch and French names (for example `beveiliging`,
`patrouille réseau`) and plain phrases like `who is on my network`.

## Confirming what is yours

This is the one job that needs *your* judgement, so it is worth doing
carefully once. After that, Huginn only asks about genuinely new things.

**The idea:** anything "unconfirmed" is a question Huginn is asking you —
*is this yours?* You answer once per device, and it stops asking.

### Naming a device

```
./ops census                          # list what is connected
./ops label 192.168.1.50 tv-lounge    # give the device at that address a name
```

(`192.168.1.50` is just an example address — use whatever `census` shows.
Your addresses might start `192.168.0.`, `192.168.1.`, `10.0.0.`, or
similar.) The name sticks to the device itself, so it survives the device
getting a new address later.

The device you **cannot** identify is the interesting one — find out what it
is before you name it. Huginn shows each device's maker as a clue (a
smart-plug brand, your router's maker, a phone manufacturer, and so on).

Devices shown as **"randomized MAC"** are almost always phones — modern
phones deliberately change their hardware ID on each network for privacy.
They come and go. Name yours once and they settle down.

### Confirming your Wi-Fi transmitters

```
./ops wifi                            # show what is broadcasting
./ops wifi trust                      # confirm every transmitter serving YOUR Wi-Fi
./ops wifi trust AA:BB:CC:DD:EE:FF    # confirm one specific transmitter
./ops wifi forget AA:BB:CC:DD:EE:FF   # take back trust from one
```

(`AA:BB:CC:DD:EE:FF` is an example hardware ID; use what `wifi` shows.)

> ⚠ **`wifi trust` with no ID confirms whatever is in range right now.** If
> a fake Wi-Fi were already running when you typed it, you would have just
> confirmed the fake one for good. Check the IDs against the labels on your
> own equipment first. This is the one place in Huginn where a careless
> click has a lasting cost.

Why so careful? One Wi-Fi network often has **several** transmitters — a
mesh system, or a router plus extenders, each broadcasting the same name.
So Huginn trusts a **list of specific transmitters**, not just "the network
name" — otherwise it would alarm on your own extender every hour.

A transmitter in another room may be **out of range** and cannot be
confirmed from where you are sitting. Carry the laptop there and run `wifi
trust` again — confirming adds to the list, it never replaces it.

Transmitters that belong to neighbours are not listed; they are only
counted. Someone else's Wi-Fi is someone else's business.

### Doing it from the console instead

**⚙ Setup → What's mine** shows both lists with a button on each item.
There is deliberately **no "confirm everything" button** — confirming in
bulk is exactly how a fake Wi-Fi gets trusted for good, and how a dozen
unexamined devices become a dozen "known" ones in a single click.

## Getting alerted

Set this up in **⚙ Setup → Who gets told** (or by editing `data/admin.json`).

| Method | Reaches you | Trade-off |
| - | - | - |
| journal | never — it only writes to a file | none; always on |
| desktop pop-up | only while you are at the computer (Linux and macOS; **not** Windows — use the phone method there) | none |
| **phone push (ntfy)** | **your phone, anywhere** | the "topic" name works like a password |
| email | anywhere, and keeps a record | stores an email password on the computer |

**The phone method (ntfy) is the one to use.** Install the free "ntfy" app,
choose a topic name nobody could guess, and enter the same name in the app
and in Huginn. Anyone who knows that topic name receives your alerts, so
keep it secret.

```
./ops admin        # show what is set up
./ops admin test   # send a real test alert through every method turned on
```

**`admin test` is the only real proof.** An alert method that is switched on
but broken looks exactly like one that works — until the night something
actually happens.

**How loud** (Setup → When & how loud): leave the level at **warning**. Set
higher and you would miss real events; a new unknown device would pass in
silence.

**Quiet hours** *discard* alerts rather than holding them, so if the
computer is usually off overnight they can only lose information. Leave them
blank unless you have a specific reason.

## The automatic schedule

Huginn sets up background checks that run on their own:

| Check | How often | What it is |
| - | - | - |
| patrol | every hour | the network watch |
| triage | every few hours | this computer's health |
| health | daily | the software's own self-check |

Each **catches up after the computer has been off** — a missed check runs
shortly after the next start-up, so an overnight shutdown becomes a
morning summary instead of a blind spot.

On Linux you can inspect them:

```
systemctl --user list-timers 'huginn-*'        # when do they next run
systemctl --user start huginn-patrol.service   # run one now
journalctl --user -u huginn-patrol -n 50       # what did the last one say
```

On Windows they are entries in Task Scheduler named "Huginn patrol".

## If Huginn itself seems broken

**Box 1 says "never recorded" but checks are running.** The heartbeat file
is `data/census/last_patrol.json`. If it is missing, a check is failing
before it finishes — on Linux, look at `journalctl --user -u huginn-patrol`.

**A button seems to do nothing.** Run any verb from the terminal, e.g.
`./ops admin`; the console lists everything that loaded. There should be
25 verbs.

**The version stamp at the bottom does not change after a restart.** An old
copy is still running. On Linux, `pkill -f 'runtime.app'` then start again.
That stamp exists precisely so a stale copy is visible instead of assumed
away.

**A "401" error in the browser.** Huginn has no login at all, so it cannot
produce that error — something else is answering on its address. Find out
what before trusting anything on the page.

**"REFUSED — this data directory belongs to …"** Huginn ties its memory
folder to the first computer that used it, so two computers cannot quietly
mix their records. If you see this, either:

- this is meant to be a **second witness** — give it its own copy and share
  only the observations folder (see *Adding a second witness* in Part 3), or
- this computer genuinely **replaced** the old one (rebuilt, new hardware) —
  run `./ops adopt`, which hands the folder over and explains what that does
  and does not fix.

---
---

# Part 3 — For whoever maintains the software

This part is for the person keeping Huginn's code healthy, not for daily
use. It is more technical.

## The one idea behind everything

> **Absence is never health.**

A check that could not run must never look like a check that passed. This
sounds obvious and is broken constantly — by empty dashboards, silent
scheduled jobs, and green lights that actually mean "no data". Several bugs
found during development were all this one mistake in different clothes,
including one in the scheduler itself: a quiet check wrote nothing, so a
check running hourly and a check that had died a week ago left *identical*
evidence. There was no wrong green light — there was no light, and the eye
reads that as calm.

Anything that looks like over-explaining — a "NOT CHECKED" line, a hollow
grey dot, a coverage count on a finding — is this rule being enforced.

## The other standing decisions

**Detect and propose, never act.** Huginn will not block, firewall,
disconnect, or reconfigure anything. A test parses the code to enforce it.
A tool that acts automatically on a home network eventually cuts off
something that mattered, gets switched off, and then protects nothing.

**Zero dependencies.** `requirements.txt` has no requirement lines, and a
test asserts it. Standard-library Python only. A tool used mid-incident must
not need a working internet connection just to start.

**Local only.** The console server listens on `127.0.0.1` (this computer
alone) and has no login. That is *only* safe because of that local-only
binding — anything able to reach the address could already run every
command. The console shows its live address in the footer so the assumption
stays visible. **If the address is ever changed away from local-only, the
write endpoints need real authentication first.**

**Reaches the internet only to send your alerts**, off by default.

**Archive, never delete.** Old data is moved aside, not destroyed.

## How the code is arranged

```
contracts/         data shapes; depends on nothing
platform_support/  ALL operating-system differences live here
engines/           anything that runs an external tool or touches disk
domains/           pure logic — facts in, findings out; no side effects
agents/            coordinate domains and engines
skills/            one verb each; thin — parse, delegate, format
runtime/           the command registry, router, and web server
```

Dependencies only ever point downward. `tools/test_architecture.py`
enforces that, and also rejects: files over 400 lines, functions over 50
lines, catch-all names like `utils.py`, running external tools outside
`engines/`, and operating-system branching outside `platform_support/`.

That last rule is why Huginn runs the same on Windows, Linux, and macOS:
every "if Windows" lives in one place, so "runs on both" cannot quietly rot
into "runs on the one I tested". `tools/test_portability.py` pretends to be
each operating system in turn and checks every command still resolves — so
a Linux test run also proves the Windows and macOS paths.

## Running the tests

```
python3 tools/test_architecture.py        # the structural rules
for f in tools/test_*.py; do python3 "$f"; done   # everything
```

A git pre-commit hook runs the architecture and load-safety checks on every
commit. The full battery is currently 45 suites and 800-plus individual
checks.

## Installing by hand

The everyday path is the installers in *Getting started*
(`Install-Huginn.bat` on Windows, `packaging/linux/install.sh` on Linux).
By hand:

**Linux** — if `./ops triage` runs, it is already installed; the rest is
just icon and schedule:

```
./packaging/desktop/install-desktop.sh          # icon + launcher
./packaging/systemd/install-timer.sh patrol      # hourly check
```

**Windows** — `packaging\windows\Install-Huginn.ps1` does the files and the
scheduled task; the `.bat` wraps it with Python detection and the desktop
shortcut. Batch and PowerShell files here are plain ASCII (PowerShell 5.1,
still the Windows default, misreads other encodings), and a test enforces
it.

## The verification disc

`packaging/build_iso.sh` builds a disc image carrying the whole platform
plus `VERIFY.cmd`. Its job is to prove the product rebuilds and passes its
tests **on a clean machine that has nothing installed** — the strongest form
of "it really works". The builder needs `pycdlib`
(`sudo apt install python3-pycdlib`); nothing on the disc does.

## Adding a second witness

See `docs/SECOND-WITNESS.md` for the full procedure. The part people get
wrong: a **virtual machine on the computer you are already watching is not a
second witness** — it shares the same network connection and so sees the
same lies. Nor is a computer on a different part of the network. It has to
be a **separate physical computer on the same network segment.** Reports
travel between them as files in a shared folder; nothing is ever accepted
over the network.

## What Huginn cannot do

Limits, not bugs, and not going away:

- **It only sees while the computer is on.** It cannot watch through a
  powered-down network card. Catching up after start-up is the best
  available answer, not a cure.
- **It sees one network segment** — the one it is plugged into.
- **It does not capture raw traffic.** Attacks are spotted by their
  symptoms, and every such finding says so.
- **Agreement is not proof.** Two witnesses can agree and both be fooled by
  one attacker; `corroborate` refuses to call agreement "safe".
- **A confirmed Wi-Fi transmitter is not a *safe* one.** A fake can copy an
  ID as easily as a name. "Confirmed" means *nothing new has appeared* — a
  weaker, honest claim.
- **It never blocks**, by choice.

## Where things live

| Path | What |
| - | - |
| `NEXT-CHAPTER.md` | the live to-do list — the only forward-looking file |
| `ARCHITECTURE.md` | the layers and the rules |
| `LONG-TERM.md` | the longer-range roadmap |
| `docs/SECOND-WITNESS.md` | the two-computer procedure |
| `docs/history/` | closed chapters and the build journal |
| `data/census/` | the memory: baselines, the change journal, observations |
| `data/OWNER.json` | which computer owns this data folder |
| `data/admin.json` | who gets alerted |
| `data/secrets/smtp.key` | the email password, locked to the owner; appears only once email is set up |

`data/` is not stored in version control — it is this computer's memory, and
it is what lets Huginn answer "is this new?". Back it up with the computer.

---
---

# Glossary

Plain-English definitions of the words used above.

- **Network / LAN** — all the devices connected together in your home or
  office (by Wi-Fi or cable): computers, phones, printers, TVs, smart plugs.
- **Router** — the box from your internet provider that connects your
  network to the internet. Every device trusts it, which is why faking it is
  a favourite attack.
- **IP address** — a device's current number on the network, like
  `192.168.1.50`. It can change over time. Ranges usually start `192.168.`
  or `10.`.
- **MAC address / hardware ID** — a device's built-in identity, like
  `AA:BB:CC:DD:EE:FF`. Unlike an IP address it normally stays fixed, which is
  why Huginn ties names to it. (Modern phones deliberately randomise theirs
  for privacy.)
- **Port** — a numbered "door" on a device that a service listens behind.
  Some open doors are normal; a few are risky, and those are what `expose`
  looks for.
- **ARP / neighbour cache** — each computer's private note of "which
  hardware ID is at which address right now". Attacks that impersonate the
  router work by poisoning this note; a second computer's separate note is
  how you catch that.
- **Access point / Wi-Fi transmitter** — the thing broadcasting a Wi-Fi
  network. One network name can come from several transmitters (a mesh, or a
  router plus extenders).
- **Evil twin** — a fake access point broadcasting the same Wi-Fi name as
  yours, hoping a device connects to it and reveals a password.
- **Verb** — one named check or action in Huginn (`census`, `patrol`,
  `wifi`, and so on).
- **Patrol** — Huginn's full round of checks, run hourly on its own or by
  the **Check now** button.
- **Finding** — one thing Huginn noticed, with how serious it is (info /
  warning / critical), how sure it is (certain / likely / possible), and a
  suggested next step.
- **Witness** — a computer running Huginn and reporting what it sees. Two
  witnesses can cross-check each other; one cannot.
- **Confirmed** — you have personally told Huginn a device or transmitter is
  yours. Being merely *seen before* does not count.
- **ntfy** — a free phone-notification app Huginn can use to reach you when
  you are away from the computer.
- **Terminal** — the typed-command window (Command Prompt / PowerShell on
  Windows, Terminal on Linux and macOS).
- **Python** — a widely used, free programming language. Huginn runs on the
  parts that come built in, so there is nothing extra to download.

---

*Found something in this manual that does not match what Huginn actually
does? The manual is the thing to fix — a document that describes a button or
a command that is not there is worse than none, because it is trusted.*
