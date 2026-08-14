# Testing `why cant-login` against your AD lab

The lab: Windows Server VM as DC (say domain `corp.local`, DC at
192.168.x.10) + the Win 11 VM joined to it. This checklist validates the
full §6.4 walk — every check maps to a competence an interviewer can ask
about (AD DNS, SRV records, Kerberos, secure channel, time hierarchy).

Run from the joined Win 11 client (`netdiag_windows_amd64.exe`) AND from
the Linux laptop (`netdiag_linux_amd64`) if it can reach the lab network —
the walk is target-based and works from any machine whose DNS can see the
domain.

## 0. Healthy baseline (everything green)

```
netdiag why cant-login corp.local
```

Expect every step ✓:
- DNS fit for AD (client DNS points at the DC)
- DC-locator SRV resolves → your DC listed
- Kerberos + GC SRV records → both resolve
- discovered DCs respond → 1 of 1
- AD port set (88/389/445/3268) → all answer
- clock inside Kerberos tolerance → "vs the DC's own clock" (netdiag
  SNTP-queries the DC directly; w32time on a DC serves NTP)
- machine secure channel → "trust intact" (Windows client only — nltest)
- machine knows a realm → CORP.LOCAL

Also save the healthy state: `netdiag baseline` and `netdiag -save adgood.json`.

## Fault scenarios (each fires a specific rule)

1. **The classic — client DNS on public resolver** (`ad_dns_public_resolver`):
   on the Win 11 client, set DNS to 8.8.8.8 → rerun → "DNS fit for AD ✗ …
   it can NEVER find the DC". This is the spec's flagship verdict. Restore DNS.

2. **Resolver-order problem** (`ad_srv_resolver_mismatch` in the walk):
   set DNS to 8.8.8.8 *primary* + DC *secondary* → the walk should show
   "only some configured resolvers know the domain — resolver order".

3. **Clock skew** (`ad_dc_clock_skew`): on the client, stop w32time
   (`net stop w32time`) and set the clock 10 minutes off → rerun →
   clock check ✗ "vs the DC's own clock". Also try to log in with a
   domain account — the Kerberos error netdiag predicts. Fix:
   `net start w32time && w32tm /resync`.

4. **Broken secure channel** (`ad_secure_channel_broken`): on the DC,
   `Reset-ADAccountPassword`? No — the clean repro: on the DC run
   `Get-ADComputer WIN11VM | Set-ADAccountPassword -Reset` (or disable the
   computer account) → on the client rerun → secure channel ✗ "reset the
   machine trust; stop looking at the network". Repair from the client:
   `Test-ComputerSecureChannel -Repair -Credential (Get-Credential corp\Administrator)`.

5. **DC down / filtered** (`ad_dcs_unreachable`): pause the DC VM (DNS
   still cached, or run from the Linux laptop pointing at a hosts entry) →
   "discovered DCs respond ✗ 0 of 1". Or leave the DC up and block ICMP+
   88/389/445/3268 inbound on its firewall → ping fails and the port set
   shows refused/filtered per port.

6. **Partial SRV zone**: delete the `_gc` SRV record in the DC's DNS zone
   → "Kerberos + GC SRV records ✗ … check the _msdcs zone". Recreate via
   `ipconfig /registerdns` + netlogon restart on the DC.

7. **compare across the fault**: `netdiag -save adbad.json` during any
   fault, then `netdiag compare adgood.json adbad.json` — the AD rule
   should appear under "findings the broken machine has".

## What to send me

Anything unexpected: the full `why cant-login corp.local` output, and for
collector errors the `-json` output. Known limitation to not report: GPO
last-processing result is not read yet (dsregcmd doesn't expose it;
needs gpresult parsing — on the remaining list).
