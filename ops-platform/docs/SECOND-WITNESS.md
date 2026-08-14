# The second witness — running Huginn on two machines

Chapter two, item 5. What it buys, what it does not, and how to set it up.

## Why

Every guard finding Huginn makes rests on **one machine's ARP cache** — and
one cache is precisely what an ARP-spoofing attacker rewrites. She has
always said so honestly (`confidence: likely`, "the packets were not
captured"). Honesty about a blind spot does not remove it.

Two hosts each holding their own cache can **disagree**. If your laptop and
your Windows box hold different MACs for the gateway, at least one of them
has been given a false answer, and that conclusion does not depend on
trusting either cache. It is the strongest single signal this tool can
produce, and a single machine cannot produce it at all.

## What it is NOT

- **Not more reach.** Both machines almost certainly sit in the same
  broadcast domain, so this does not see another VLAN or a different
  segment. It widens *confidence*, not *coverage*.
- **Not proof.** Two hosts can agree and both be lied to — one attacker
  poisoning both caches produces perfect consensus. Corroboration raises
  confidence; it never establishes truth, and every message says so.
- **Not a network service.** Nothing listens. No port is opened on either
  machine. Huginn stays loopback-only on both.

## How it works

Each host writes one small JSON file describing what it just saw:

```
data/census/observations/observation-<machine>.json
```

Written on every patrol, overwritten each time — it is a *current
statement*, not a history (the guard timeline already keeps history). Any
host that can read another host's file gains a witness.

**Moving the file between machines is your choice, deliberately.** Building
a transport would mean building a listener, and a security tool that opens
a port to improve its security posture has made a trade nobody asked for.

Reasonable options, cheapest first:

| Method | Notes |
| - | - |
| Syncthing / Nextcloud folder | Both machines point `observations/` at a synced directory. Set and forget. |
| SMB share on the NAS | Mount it on both; simplest if a share already exists. |
| `scp` from a scheduled task | One-directional is enough — whichever host you read `corroborate` on needs the other's file. |
| USB stick | Works. Not fresh enough to count as a witness for long (see below). |

⚠ **A shared folder is a shared trust boundary.** Anything that can write
into it can hand a host a fabricated observation. This is the reason
corroboration is worded as raising confidence rather than proving anything.

## ⛔ What CANNOT be a second witness

Learned by trying, 2026-07-27. Each of these looks like it should work.

### A VM on the machine you are already watching

Two objections, either one fatal.

**Shared fate.** A guest is compromised when its host is. Two witnesses that
fall together are one witness, and the entire value of corroboration is
independence.

**On Wi-Fi it cannot even reach the LAN.** If the host connects over Wi-Fi,
the guest cannot be bridged onto the physical network at all — 802.11
associates ONE MAC per client and the access point silently drops frames
from a second MAC behind it. Bridge mode and every macvtap mode fail. This
is the standard, not a virt-manager setting you have missed.

A routed network with proxy ARP *does* work on Wi-Fi, and is worthless
here: the guest's ARP cache would be built through the host, so it inherits
whatever the host was told. **A witness that inherits its answer from the
machine it is meant to check is not a witness.**

One more, even on Ethernet: macvtap deliberately blocks host↔guest traffic,
so the observation files need a second NIC — leaving the guest with two
default routes and an ambiguous answer to "which gateway did you see?",
the one question corroboration depends on being unambiguous.

### A machine on a different subnet

If the two hosts have different gateway IPs they are on different broadcast
domains. Neither can see what the other sees, and their gateway MACs are
two unrelated routers.

Huginn detects this and refuses to compare them — `corroborate` reports
`split_across_segments` and names each network. It did not always: the
first version compared everything against everything, and the first real
two-machine run would have raised a **critical ARP-spoofing alert** built
entirely out of a VM's NAT interface. A tool that invents attacks teaches
its operator to disbelieve it.

### What DOES work

Any always-on device with Python that holds its own ARP cache on the same
segment: a Raspberry Pi, a NAS that runs containers, a second laptop on
Ethernet, a desktop. Independent hardware, independent cache, same network.

---

## Setting it up — the actual procedure

### 0. Choose the shared folder

Anything both machines can read and write. Cheapest options:

| Option | Linux path | Windows path |
| - | - | - |
| Syncthing folder | `~/Sync/huginn` | `C:\Users\you\Sync\huginn` |
| Share on the NAS | `/mnt/nas/huginn` | `\\nas\huginn` |
| Windows share | mounted via CIFS | `C:\huginn-shared` (shared) |

Both machines point at it with **`HUGINN_OBSERVATIONS_DIR`**. Nothing else
needs to agree, and neither machine edits code.

### 1. Linux side (this machine)

Add the variable to the patrol unit so the SCHEDULED runs use the shared
folder, not just the ones you type by hand:

```bash
systemctl --user edit huginn-patrol.service
```

Add:

```ini
[Service]
Environment="HUGINN_OBSERVATIONS_DIR=/home/alex/Sync/huginn"
```

Then:

```bash
systemctl --user daemon-reload
systemctl --user start huginn-patrol.service
./ops corroborate                      # should name this host
```

⚠ **The variable must be on the unit, not only in your shell.** A witness
that only writes when a human runs the verb goes stale within 90 minutes of
you walking away — which is exactly when a second opinion would have been
worth having.

### 2. Windows side

Copy `ops-platform\` to the Windows box (from the verification disc's
extracted payload, or over the network), then in PowerShell:

```powershell
cd <where you put it>\packaging\windows
.\Install-Huginn.ps1 -SharedObservations "C:\Users\alex\Sync\huginn"
```

That script:

- finds Python and **fails if there is none**, before installing anything
- copies the platform to `%LOCALAPPDATA%\Huginn` — **excluding `data\`**,
  so the second witness builds its own view rather than repeating the
  first's
- sets `HUGINN_OBSERVATIONS_DIR` for your user
- **runs one patrol to prove it works before scheduling it**
- registers an hourly Scheduled Task, plus at logon, with
  `StartWhenAvailable` — Task Scheduler's equivalent of systemd's
  `Persistent=true`, so a window the machine spent switched off is caught up
  rather than lost

No administrator rights. A user-level task and a user-level directory: a
monitoring tool that demanded admin to watch a LAN it can already see would
be asking for trust it does not need.

### 3. Confirm

On either machine:

```bash
./ops corroborate
```

**Two names must appear.** Until then this is one ARP cache — which is what
an attacker rewrites — and the verb will keep saying so:

```
Only ONE host is currently witnessing: example-host.
Nothing can be corroborated ...
```

### 4. Prove it actually catches something

Corroboration that has never fired is an assumption. On the Windows box,
with the shared folder in place, add a false ARP entry for the gateway:

```powershell
netsh interface ip add neighbors "Ethernet" 192.168.1.1 de-ad-be-ef-00-99
./ops corroborate          # must now report a CRITICAL disagreement
netsh interface ip delete neighbors "Ethernet" 192.168.1.1
```

If it stays quiet, the two machines are not sharing the folder — check that
`HUGINN_OBSERVATIONS_DIR` resolves to the same place on both, and that both
files are actually in it.

## Freshness — why an old witness stops counting

An observation older than **90 minutes** is not evidence about now. A
machine that has been off since yesterday describes yesterday's network,
and comparing it against a live reading would manufacture disagreements out
of nothing but time.

Past that window a host stops being counted **and is reported as stale** —
never silently dropped, because a corroboration that quietly shrank back to
one witness looks identical to one that succeeded.

90 minutes matches the hourly patrol: any machine that is awake and
patrolling has written inside the window; any machine that has not is
genuinely not a witness.

**This matters here specifically:** the Windows box is not always on. When
it is off it is not a witness, `corroborate` will say so, and that is the
correct answer rather than a fault to work around.

## What alerts

`patrol` runs the cross-check on every pass and **alerts on a gateway-MAC
conflict even when the local guard saw nothing** — because the local cache
can look perfectly consistent while being the one that was rewritten. That
is the whole attack a single host cannot see, so it must not depend on that
host having also noticed something.

Partial visibility — devices one host sees and the other does not — is
`info` and never alerts. On a switched network a host only holds ARP
entries for machines it has recently talked to, so two hosts routinely see
different subsets. Alerting on it would be hourly noise.
