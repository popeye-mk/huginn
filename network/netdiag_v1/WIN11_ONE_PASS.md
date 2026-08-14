# One-pass acceptance on the Win 11 client (netdiag 0.6.0-v1.3)

Everything still open lives in this one checklist, so the VM has to be built
once and driven once. Run it on a **Win 11 client joined to corp.local** —
not on the DC. The DC's own campaign is already closed (V1_STATUS.md).

Copy `netdiag_windows_amd64.exe` in as `netdiag.exe`, open PowerShell **as
Administrator**, and run the lines one at a time. Multi-line pastes glue
themselves together in PowerShell and silently skip steps.

---

## 0. Version and healthy baseline

```powershell
.\netdiag.exe -version          # must read 0.6.0-v1.3
```
```powershell
.\netdiag.exe
```
```powershell
.\netdiag.exe baseline
```
```powershell
.\netdiag.exe -save clientgood.json
```

Expect: all blame segments ✓, findings few and low-severity, and the honest
skip list naming anything this VM can't expose. **`wifi` should now report
real data if the VM has a Wi-Fi adapter passed through**; on a virtio NIC it
will skip with "no WLAN service", which is correct, not a failure.

---

## 1. The member secure channel (only testable here — the DC says
"not applicable")

```powershell
.\netdiag.exe why cant-login corp.local
```

Expect every step ✓, and the secure-channel line to read **"trust intact"**
rather than the DC's not-applicable message.

### Break it (scenario 4). Domain is live — this is the one destructive test.

On the **DC**:
```powershell
Get-ADComputer <WIN11NAME> | Set-ADAccountPassword -Reset
```
On the **client**:
```powershell
.\netdiag.exe why cant-login corp.local
```
Expect: **machine secure channel ✗** — "reset the machine trust; stop looking
at the network", and the `ad_secure_channel_broken` rule in the findings.

Repair, on the client:
```powershell
Test-ComputerSecureChannel -Repair -Credential (Get-Credential corp\Administrator)
```
```powershell
.\netdiag.exe why cant-login corp.local     # back to ✓
```

---

## 2. Clock skew (scenario 3)

```powershell
net stop w32time
```
```powershell
Set-Date (Get-Date).AddMinutes(10)
```
```powershell
.\netdiag.exe why cant-login corp.local
```

Expect: **clock inside Kerberos tolerance ✗** with the offset measured
against the DC's own clock, plus `ad_dc_clock_skew`. Bonus: try logging in
with a domain account and watch the Kerberos error netdiag predicted.

Revert:
```powershell
net start w32time
```
```powershell
w32tm /resync
```

---

## 3. DC unreachable (scenario 5)

Pause the DC VM in virt-manager, then on the client:
```powershell
.\netdiag.exe why cant-login corp.local
```

Expect: **discovered DCs respond ✗ 0 of 1**, `ad_dcs_unreachable`, and the
blame partition pointing at the DC/domain segment — not at this machine.
Resume the DC afterwards.

---

## 4. Print spooler — the local half of cant-print (new in 0.6.0)

```powershell
.\netdiag.exe why cant-print <printer-host-or-ip>
```

Expect the two new L7 checks **before** the transport ones: spooler running,
queue moving. Then break it:

```powershell
net stop spooler
```
```powershell
.\netdiag.exe why cant-print <printer-host-or-ip>
```

Expect: **print spooler is running ✗** — "the Print Spooler service is
STOPPED … no network fix will help", `print_spooler_stopped` critical, and
the walk stopping there instead of blaming the network.

```powershell
net start spooler
```

If the VM has no printer configured, the queue check should **skip**
honestly ("queue not readable") rather than report green.

---

## 5. watch — the time-domain verb (new in 0.6.0)

Baseline-aware, so run it after step 0's `baseline`.

```powershell
.\netdiag.exe watch -duration 2m -interval 5s
```

Expect: a clean 2-minute window ending in "No events" and a verdict that
explicitly refuses to call that proof of health. Then catch a real fault —
disable the NIC mid-run from another window:

```powershell
.\netdiag.exe watch -duration 2m -interval 5s
```
…and while it runs, in a second PowerShell:
```powershell
Get-NetAdapter | Where-Object Status -eq 'Up' | Disable-NetAdapter -Confirm:$false
```
```powershell
Get-NetAdapter | Enable-NetAdapter -Confirm:$false
```

Expect: a timestamped **link went DOWN** event, then **link came back up**,
and a verdict naming a flap that WAS caught in the window — with the times.
Ctrl-C during any run must still print the summary.

Periodicity: if you want to see the rhythm detector fire, disable/enable the
NIC three or four times at a roughly even spacing during a longer run; the
summary should report "recurred N× on a regular ~X cycle".

---

## 6. compare, end to end

```powershell
.\netdiag.exe -save clientbad.json      # while something above is broken
```
```powershell
.\netdiag.exe compare clientgood.json clientbad.json
```

Expect the ranked delta and "findings the broken machine has".

---

## What to send back

The full output of anything that surprises you, plus `-json` for collector
errors. Known and deliberate absences on Windows: duplex, path-MTU, the IPv6
default-route fact, per-rule firewall reconciliation, and GPO last-processing
result (needs gpresult parsing — still on the remaining list).
