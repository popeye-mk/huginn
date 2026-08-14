# Windows verification — netdiag 0.9.15

Paste **one line at a time**. (Multi-line pastes glued commands together last
time, and a "pass" turned out to be a run where the fault was never injected.)

The binary is `netdiag_windows_amd64.exe` in this folder. Copy it to the
Windows machine; rename it `netdiag.exe` if you like.

---

## What this is really testing

Everything below is a bonus except **section 2**. That one matters because
`link_primary_is_wireless` reads a struct offset I reasoned about from the
documented `MIB_IFROW` layout and have never watched execute. The DHCP "255"
bug came from exactly this — a struct offset that looked right on paper.

The other fields from that same row (`mtu`, `speedMbps`, `operStatus`) were
field-verified in earlier runs, which is good evidence the row layout is right.
`dwType` sits between `dwIndex` (512) and `dwMtu` (520), so 516 should be
correct. *Should be.* That is what this checks.

---

## 1. The tool proves itself first (5 seconds, no network)

```
.\netdiag.exe selftest
```

Expect `18/18 passed`. If this fails, stop — nothing below is trustworthy, and
the failure text says which property broke.

---

## 2. THE ONE THAT MATTERS: is the medium read correctly?

First, Windows' own answer:

```
Get-NetAdapter | Select-Object Name,InterfaceType,Status
```

`InterfaceType` **6** = ethernet, **71** = 802.11 wireless. Note which adapter
is `Up`.

Now netdiag's answer:

```
.\netdiag.exe -json | Select-String link_primary_is_wireless
```

Then, for context:

```
.\netdiag.exe -json | Select-String "link_primary_interface|link_speed_mbps"
```

**How to read the result**

| Adapter InterfaceType | netdiag says | Verdict |
|---|---|---|
| 6 (ethernet) | `false` | correct — but see the warning below |
| 71 (wireless) | `true` | **correct, and this is the one I need** |
| 71 (wireless) | `false` | **BUG — send it to me; do not trust `why slow` on laptops** |
| 6 (ethernet) | `true` | **BUG — send it to me** |

**The warning, stated plainly:** if the offset is wrong, the value it reads is
almost certainly some other DWORD (1500, an interface index), and none of those
equal 71 — so a wrong offset shows up as `false` on *everything*. **A wired
machine reporting `false` therefore proves almost nothing.** Only a genuinely
wireless Windows machine reporting `true` proves the offset is right.

Your Win 11 VM is virtio/QEMU — no Wi-Fi — so it can only produce the weak half
of this test. If you have a real Windows laptop on Wi-Fi anywhere, that single
run is worth more than everything else on this page.

**Why I care this much:** `link_negotiated_low_wired` fires on a wired link
under 100 Mbps. If a Wi-Fi laptop wrongly reports `is_wireless=false` and the
radio is having a bad afternoon at 65 Mbps, netdiag tells the user to replace a
cable they do not have. Confidently wrong — the exact species of bug this
project keeps hunting.

---

## 3. The L2 rules do not misfire on a healthy machine

```
.\netdiag.exe
```

On a healthy wired VM, **none** of these should appear:

- `link_negotiated_low_wired`
- `dot1x_port_unauthorized`
- `neigh_mostly_incomplete`
- `wifi_open_network`

If any fires, paste the whole block. A false positive is a bug even when the
underlying reading is real.

---

## 4. The ticket export

```
.\netdiag.exe ticket
```

Read it as though someone handed it to you cold. Three checks:

1. **RULED OUT** lists the segments that measured healthy.
2. **NOT CHECKED** lists collectors that skipped, each with a reason.
3. Nothing reads as "all clear" while findings are listed above it.

Then the redacted form — the one that leaves the company:

```
.\netdiag.exe ticket -anon
```

Hostname must be `redacted-host`. No internal hostnames, no public IPs.

On the DC, the AD flavour (this exercises the bug #22 fix — the evidence that
used to vanish under `-anon`):

```
.\netdiag.exe ticket cant-login -anon
```

The AD findings must still carry their evidence figures. A finding with an
empty `evidence:` line means bug #22 is not fully fixed.

---

## 5. `why slow` offers the load test

```
.\netdiag.exe why slow
```

If the walk found nothing, the last block should say the checks measure an
**idle** link and point at `netdiag speed`. If the walk *did* find something,
that block must be **absent** — the offer must not bury a real finding.

It must only *offer*. If it starts moving data on its own, that is a serious
bug: `why slow` belongs to the read-only promise.

---

## 6. Menu still navigable

```
.\netdiag.exe menu
```

Entries 17 (*Write a ticket to hand over*) and 18 (*Check that netdiag itself
is working*) are new. Check that `0` backs out of a prompt without dropping you
out of the program.

---

## What to send back

For anything that looks wrong: the whole console block rather than a summary —
the exact numbers are usually where the bug is. For section 2, send the
`Get-NetAdapter` output alongside netdiag's, so the two answers can be compared
directly.
