# netdiag 0.9.0-v1.5 — the full test pass

Everything is built. This is the one-sitting acceptance run across all three
machines. Drive it from the menu (`netdiag menu` / double-click
`netdiag.bat`) — that is now the intended interface, and testing it *as the
interface* is part of the point.

Work down the list. Paste anything that surprises you; a wrong sentence is a
bug even when the numbers are right.

---

## A. Laptop (Zorin) — the install path, 15 min

```
cd '~/huginn /netdiag_v1'
sudo ./install_linux.sh
```
Expect: installed to /usr/local/bin, cap_net_raw granted, added to the
applications menu.

Then, as a normal user (no sudo):

| # | Do | Expect |
|---|----|--------|
| A1 | `netdiag menu` → **1** | progress line while it runs, then the blame table. Wi-Fi facts real (SSID/BSSID/channel/signal) |
| A2 | menu **11** (baseline) | saved for this location |
| A3 | menu **13** (devices) | your home devices listed with vendors — router, phones, printer |
| A4 | `netdiag devices -authorized` | the AUTHORIZATION text, typed `yes` required, then a fuller list |
| A5 | menu **14**, answer with your real contracted speed | consent prompt → grade A–F + delivered vs paid |
| A6 | menu **4** (Wi-Fi) | channel occupancy, neighbour APs, 802.1X state |
| A7 | menu **15** → Enter | HTML report written; open it in a browser |
| A8 | `netdiag menu` → **10**, 2m, then unplug/replug Wi-Fi mid-run | bell + FAULT CAUGHT banner, timeline with times |
| A9 | Find **netdiag** in the Zorin applications menu | opens a terminal at the menu |

**The interesting one is A5.** Your laptop has a real internet path, so the
bufferbloat grade is meaningful. If it comes out D or F, that is a genuine
finding about your home router, not a tool bug.

---

## B. Win 11 client — the client half, 20 min

Deliver: on the laptop
`genisoimage -o /tmp/netdiag14.iso -J -r -V NETDIAG14 netdiag_windows_amd64.exe netdiag.bat netdiag-report.bat QUICKSTART.md`
then attach, and in the VM `copy D:\*.* .` + rename the exe to `netdiag.exe`.

| # | Do | Expect |
|---|----|--------|
| B1 | `.\netdiag.exe -version` | **0.9.0-v1.5** |
| B2 | Double-click **netdiag.bat** | the menu opens with no typing |
| B3 | menu **1** | progress line, DHCP server 10.0.0.10, healthy blame table |
| B4 | menu **13** (devices) | the DC and gateway listed; 52:54:00 shown as *QEMU/KVM virtual* |
| B5 | `net stop spooler` then menu **8**, any name | walk stops at **print spooler ✗** — "no network fix will help" |
| B6 | `net start spooler`, menu **8** again | spooler ✓, then the name/transport checks |
| B7 | menu **7**, `corp.local` | all green incl. "trust verified (fresh authentication)" |
| B8 | menu **15** | HTML report on the VM; check the hygiene section appears |
| B9 | Double-click **netdiag-report.bat** | report written to Desktop AND opened in the browser |

### New in this build — hygiene (check the scan output of B3)

Expect a hygiene section naming: LLMNR/NetBIOS/mDNS if enabled (Windows
defaults say they will be), SMBv1 state, RDP NLA state, and any risky
listeners. On a domain-joined Win 11 client, `hygiene_poisoning_surface`
firing is CORRECT — those protocols are on by default and that is the point
of the finding.

Optional break/fix, if you want to see it flip:
```powershell
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -Value 0 -Force
```
(create the key first if missing) → rerun menu **1** → LLMNR should drop off
the list. Revert by deleting the value.

---

## C. Windows Server DC — the server half, 10 min

Same delivery. The DC is where `devices` earns its keep.

| # | Do | Expect |
|---|----|--------|
| C1 | menu **13** | the client + gateway, vendors resolved |
| C2 | `.\netdiag.exe devices -authorized` | authorization text naming 10.0.0.0/24 and 254 addresses; type `yes` |
| C3 | `.\netdiag.exe devices -save inv.json` | saved |
| C4 | start any other VM, then `.\netdiag.exe devices -since inv.json` | the new machine listed under **NEW** |
| C5 | menu **1** | scan clean, hygiene section present; on a DC expect SMB/RPC listeners flagged as worth-checking — correct, not alarming |
| C6 | menu **7**, `corp.local` | still "this machine IS a domain controller — not applicable" |

**C4 is the shadow-IT demo** and the best thing to show someone: snapshot,
plug something in, and the tool names what appeared, by vendor.

---

## What I am specifically watching for

1. **Wrong sentences.** Every finding claims something; if a claim does not
   match what you know is true on that machine, that is the highest-value bug.
2. **False greens.** Anything reported ✓ that is not actually fine. This has
   been the worst bug class all along (the cached secure channel).
3. **Menu friction.** Anything you had to think about twice.
4. **The hygiene findings on a DC** — servers legitimately listen on things a
   laptop should not, and the wording has to respect that.

## Known and deliberate

- 16% upstream loss in the lab: real, not a tool bug — it is the libvirt NAT path.
- `nic_power` / `wifi` skip on VMs: correct, virtio adapters expose neither.
- The unsigned .exe still triggers SmartScreen: needs a code-signing
  certificate, which has to be bought in your name.
