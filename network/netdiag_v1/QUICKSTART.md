# netdiag — quick start

You do not have to remember anything on this page. Only the first section.

## Install it once (Zorin / Ubuntu / any Linux)

```
./install_desktop.sh
```

No sudo. You get a **desktop icon**, an entry in the applications menu (search
for "network", "wifi" or "slow"), and `netdiag` as a command.

**Double-click the icon** and the guided menu opens — that is the whole
interface. (The launcher also defines three right-click shortcuts, but most
Linux desktops, Zorin included, only show those in the app grid or on a pinned
taskbar icon — do not go looking for them. Everything they do is in the menu:
scan is 1, ticket is 19, selftest is 20.)

To remove everything: `./install_desktop.sh --uninstall`. Your saved baselines
survive that.

**Windows:** copy `netdiag_windows_amd64.exe` to the machine and double-click
`netdiag.bat`, or run `.\netdiag.exe menu`.

**Optional, one line.** Pings need a capability that installing without sudo
cannot grant. Without it netdiag falls back to TCP probes and says so in the
report — nothing breaks, the numbers are just slightly less direct:

```
sudo setcap cap_net_raw+ep ~/.local/bin/netdiag
```

## The one thing to remember

```
netdiag menu
```

A numbered list under five headings. Pick a number — **or type a word.**
Typing `print` jumps to the printing check; `slow`, `wifi` and `ticket` work
the same way, so you never have to count rows.

```
  SOMETHING IS WRONG          WATCH AND COMPARE
   1. Check this computer      10. Watch for a problem that comes and goes
   2. I have no internet       11. Remember this place as healthy
   3. Everything is slow       12. What changed since it was healthy?
   4. Wi-Fi problems           13. Show the baselines saved here
   5. It drops now and then    14. Compare two machines (working vs broken)
   6. Can't reach a server
   7. Can't log in to domain   LOOK AROUND
   8. Can't print              15. Who else is on this network?
   9. Can't connect with RDP   16. Test speed and call quality
                                   (USES DATA — asks first)
  HAND IT OVER                 TOOLS
  17. Save a report to a file  20. Check that netdiag itself is working
  18. Explain in plain language 21. Look something up (reference ONLY —
  19. Write a ticket to hand over   not a scan of this machine)
```

`0` goes back from any prompt. `q` quits.

## If you prefer typing

The six that cover almost everything:

```
netdiag                             check this machine now
netdiag why no-internet             find the first broken layer
netdiag why slow                    loss, latency, jitter, DNS timing
netdiag why cant-login corp.local   domain sign-in problems
netdiag ticket                      a summary to hand to someone else
netdiag baseline                    remember this place while it works
```

Add `-for-user` to any of them for a version you can read out to a
non-technical person.

## Do you trust this build?

```
netdiag selftest
```

Twenty-two checks in about five seconds. No network, no system state, nothing
changed — it pushes fixed facts through the real rules and the real verdict
logic and confirms the sentences that come out are still correct. Every check
is a mistake this tool has actually made in the field and must never make
again.

Expect `22/22 passed`. **Exit code 0 means the reasoning is intact; 1 means do
not believe this binary's verdicts.** Worth running after copying the tool to
a customer's machine, or if you have hand-edited `kb.json`:

```
netdiag selftest -kb my-rules.json
```

## Handing a problem to someone else

```
netdiag ticket
```

Plain text, no markdown, safe to paste into any ticket system. Two sections
that no other output has:

- **RULED OUT** — what was measured healthy, so the next person does not
  re-test your LAN.
- **NOT CHECKED** — what nobody measured, with the reason. Without this, a
  ticket quietly implies the whole machine was examined.

Before it leaves the company:

```
netdiag ticket -anon           hostnames and public IPs removed
netdiag ticket slow -o case-1234.txt
```

## The habit that pays for itself

**Run `netdiag baseline` while the network is healthy**, at every place you
work. Later, when it is not:

```
netdiag -diff
```

It tells you exactly what changed — a new gateway MAC, a different DHCP
server, loss that was not there before. That list is usually the fault.

The last **ten** snapshots per network are kept, so you can also ask what
changed since a particular day:

```
netdiag baseline -list          the dates it has
netdiag -diff -against 2        against the 2nd newest
netdiag -diff -against 7d       as it was a week ago
netdiag -diff -against 2026-07-14
```

If you ask for a day it does not have, it **fails and tells you the oldest it
has** rather than quietly comparing against a different one. A diff against
the wrong day looks like evidence.

**When one machine works and another doesn't**, run `netdiag -save good.json`
on the working one and `netdiag -save bad.json` on the broken one, then
`netdiag compare good.json bad.json`. It ranks the differences that matter.
(Also in the menu: *Compare two machines*.)

A few power flags stay command-line only: `-json` (machine-readable output),
`-anon` (redact before sharing), `-kb rules.json` (your own rule file),
`-since 48` (widen the event window). Any command lists its flags when given
one it does not know.

## What it will never do

It does not change your settings, install a service, run in the background, or
send anything anywhere. Every run says so at the bottom, and that line is the
truth: it reads your machine and talks to your own gateway and resolver,
nothing else.

The one exception is `netdiag speed`, which deliberately fills your link to
measure it. That is why it is a separate command, states how much data it will
use, and asks before starting.

If something could not be measured, it says so instead of showing green.
**"Not checked" is never the same as "fine"** — and neither is "nothing
failed". A clean run means the checks that ran found nothing, which is a
smaller claim than "your network is healthy", and netdiag will not make the
bigger one.
