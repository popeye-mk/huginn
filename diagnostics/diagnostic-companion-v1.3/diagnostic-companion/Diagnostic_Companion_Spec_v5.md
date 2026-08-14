# Diagnostic Companion — Design Spec (v5)

A cross-platform (Windows + Linux) troubleshooting tool that collects system diagnostics, translates cryptic errors into plain-language likely causes, and feeds straight into the Ops Console's ticketing layer — with no agent, no server, and no dependency on the machine still being able to boot.

> **What changed in v5:** the competitive positioning is rewritten to survive contact with someone who knows osquery and RMM tooling; a Constraints & Non-Functional Requirements section now covers privileges, timeouts, read-only guarantees and AV reputation; KB governance, data governance and a threat model are added; and the collector set is completed (including the two collectors v4 referenced in triage weights but never defined). See the changelog at the end.

---

## 1. Positioning — What Exists Today (honest version)

v4 compared this tool only against opponents it beats easily. That is a weak table, and the first person who knows this space will say *"isn't this osquery?"* or *"isn't this what TacticalRMM does?"*. Both objections are answered here, up front.

| Tool | What it genuinely does well | Where it stops |
|---|---|---|
| **osquery** | Cross-platform system state exposed as a unified SQL schema. Mature, well-tested, the real prior art for "same data shape on every OS". | **Data, not diagnosis.** It answers questions you already knew to ask. No interpretation, no plain-language findings, no severity, no next step, no ticket concept. Needs an operator who already knows what "reallocated_sector_ct > 0" means. |
| **TacticalRMM / NinjaOne / Atera / GLPI agent** | Fleet inventory, health monitoring, alerting, ticketing — genuinely overlapping with the fleet board and ticket hook. | **Requires an agent, a server, and (mostly) a licence.** Nothing runs on an unbootable machine, a machine that was never enrolled, or a stranger's PC. Alerts are threshold-based, not causal. Interpretation is still the technician's job. |
| **Sysinternals suite / Autoruns / Process Explorer** | Best-in-class depth on Windows internals. | Windows-only, expert-only, one tool per question, no report, no aggregation, no ticket. |
| **Dell SupportAssist / Lenovo Vantage / HP Support Assistant** | Vendor hardware checks with real driver knowledge, and they do interpret. | One vendor, one OS, consumer/warranty-funnel oriented, no fleet view, no ticket integration, no extensibility. |
| **DxDiag / msinfo32 / Get-NetView** | Fast raw dumps that every Windows tech already knows. | Windows-only, raw, no interpretation, no diff, no workflow. |
| **ESET SysInspector** | Deeper snapshot with some risk flagging. | Windows-only, generic risk scoring, not helpdesk-workflow aware. |
| **sysinfo-rs / systeminformation** | Cross-platform system data as a *library*. | A building block for developers, not a tool for a technician. |
| **Linux `sysdiag` / distro scripts** | Raw log + hardware dump. | Linux-only, no interpretation, no Windows counterpart. |
| **Iolo / Kaspersky "PC checkup"** | Consumer-friendly health score. | Windows-only, sales funnel, opaque scoring, no support workflow. |

### The honest moat

Cross-platform data collection is **not** novel — osquery did it properly years ago, and claiming otherwise is the fastest way to lose an interviewer's trust. The defensible combination is narrower and stronger:

1. **An interpretation layer, not a query layer.** osquery answers questions; this answers *"what is wrong with this machine and what do I do?"* — in the user's language, with a severity and a next step.
2. **Zero agent, zero server, zero enrolment.** One signed binary on a USB stick works on a machine that was never in anyone's inventory, including one that won't boot.
3. **Causal grouping, not alert lists.** Root-cause chains and fleet correlation collapse six symptoms into one cause and one ticket. Threshold alerting does the opposite.
4. **A KB that grows from your own resolved tickets.** The tool gets better at *your* environment specifically — which is the one thing a downloaded product structurally cannot do.
5. **It starts at the complaint.** `diag why slow` mirrors how tickets actually arrive; every tool above starts at the machine.

Anything beyond those five is a nice-to-have, not a claim.

---

## 2. Goal

Run one command (or click one button in the Ops Console), get a plain-language diagnostic summary instead of a wall of raw logs, and have it attach itself to a ticket automatically — on Windows or Linux, online or offline, booted or not.

---

## 3. Constraints & Non-Functional Requirements (new in v5)

Features were never the risk in this design; the operational realities were. These are requirements, not aspirations, and each one has a test.

### 3.1 Privilege model

The tool must be useful **without elevation** and must say so clearly when it is degraded.

| Tier | Runs as | Available |
|---|---|---|
| **Unprivileged** | normal user | network, DNS, Wi-Fi (partial), disk free space, uptime, processes, user-scope logs, clock, proxy, M365 client state, activation state |
| **Elevated** | root / Administrator | SMART, minidumps, full event log, firewall state, `dsregcmd`, TPM/Secure Boot, USB tree details, service enumeration, certificates (machine store) |
| **Offline/live-boot** | root, on the target's disk | disk/SMART, filesystem state, mounted logs, installed OS version, boot config |

- `diag run` never *requires* elevation; it runs what it can and marks the rest as `skipped: insufficient_privileges`
- `diag run --explain-privileges` prints exactly which findings are unavailable and why — so a technician knows whether to bother re-running as admin
- Elevation is never silently requested; a diagnostic tool that pops UAC unprompted is a tool people stop trusting

### 3.2 Read-only guarantee

**The collector never writes to the target machine.** No registry writes, no config changes, no cache clearing, no log rotation, no temp files outside a single explicitly-specified output path.

- Enforced by convention *and* by test: the collector test harness runs against a filesystem snapshot and asserts zero mutations outside the output path
- `diag fix` is the **only** component permitted to change anything, is opt-in, dry-run by default, and lives in a separate module that the collector cannot call
- This is stated on the first page of the README, because "what does this thing do to my machine?" is the first question anyone sensible asks

### 3.3 Timeouts and partial results

The most important use case — a dying disk — is exactly the case where collection hangs. `smartctl` against a failing drive can block for minutes; a WMI query on a sick Windows box can block forever.

- Every collector declares a **timeout** (default 10s, `smart` 30s, `traceroute` 15s) and a **kill policy**
- A timed-out collector yields `status: timeout` with whatever partial data it had — it never fails the run
- **A collector that times out is itself a finding**: `smart_read_timeout` → *"The disk did not answer a health query within 30 seconds. On a healthy disk this is instant. Treat this as a strong failure signal, not a tool error."*
- Global budget: a full `diag run` completes in **under 60 seconds** on a healthy machine, or reports which collectors it dropped. Triage mode (`diag why …`) targets **under 15 seconds**
- Every collector runs in a subprocess with a hard kill, so no hung vendor tool can wedge the run

### 3.4 Absence is never health

A skipped, failed or timed-out collector must be visible in every output format. Silence must never render as green.

- Each report ends with a **"Not checked"** block listing every collector that did not produce data, with the reason (privileges, not applicable, timeout, error)
- `diag simple` shows a grey line, never omission: `⚪ Disk health — could not check (needs administrator)`
- The health score deducts nothing for unchecked items but **caps confidence**: a machine with 4 skipped collectors cannot report "healthy", only "no problems found in what could be checked"

### 3.5 Confidence, and being wrong safely

A helpdesk tool that is confidently wrong costs more than a tool that says nothing. Every finding carries a confidence level, and the language changes with it.

```yaml
- id: disk_free_critical
  confidence: certain      # certain | likely | possible
  finding: "Disk space critically low (4% free)."
```

- `certain` — a directly measured fact ("disk is at 4%"). Stated flatly.
- `likely` — a strong inference ("this is probably why the service crashed"). Hedged in the wording, and the evidence is shown next to it.
- `possible` — a correlation worth checking. Rendered in a separate "worth checking" section, never in the headline.
- Only `certain` and `likely` findings can be a chain's `root`; only `certain` findings may drive an exit code of `2`

### 3.6 Performance and footprint

- Full sweep < 60s healthy / < 120s degraded, single-threaded worst case
- Peak RSS < 150 MB (it runs on sick machines with pressure already)
- Binary < 40 MB
- Zero network egress unless `--ticket`/`--new`/`--remote` is passed. The default run is **offline by construction**, and this is asserted in test.

### 3.7 Graceful degradation, everywhere

The design principle already applied to unmatched log lines is now global and explicit: **unknown → show the raw data; unavailable → say so; unreachable → fall back to local.** No path in the tool may end in an empty screen or a silent success.

---

## 4. Part A — Collector

Runs locally on the target machine, remotely via SSH/WinRM from the Ops Console, or offline from a Ventoy live boot.

### 4.1 Core collectors (always run)

- **Network:** IP config, default gateway, DNS servers, DNS resolution test against 2–3 known-good domains, ping + traceroute to gateway and a public target
- **System:** OS version/build, uptime, last boot time/reason, disk space per volume, CPU/RAM usage snapshot
- **Services/processes:** key services running vs. expected (print spooler up? sshd/WinRM listening?), top CPU/RAM consumers
- **Logs:** last N error/warning entries from `journalctl -p err` (Linux) or `Get-WinEvent` filtered to Error/Critical (Windows)

### 4.2 Optional collectors (auto-skip when not applicable)

Carried over from v4:

- **Wi-Fi (laptops):** SSID, signal strength (RSSI), band/channel, link speed, driver in use — half of real "internet is slow" tickets are just weak Wi-Fi
- **Hardware health:** SMART per disk (reallocated sectors, pending sectors, SSD wear level), battery health % and cycle count, CPU temperature — catches "this disk is dying" *before* the crash ticket
- **Security posture:** firewall enabled?, AV/rkhunter last scan result, pending OS updates count (reuses `patch_check.py` from the Ops Console if present)
- **Clock & time sync:** NTP sync status and drift in seconds — clock skew silently breaks Kerberos/AD logins and TLS
- **Certificates:** machine/VPN/802.1X certificate expiry, plus system trust-store sanity — expired certs generate the most bizarre-looking tickets in existence
- **VPN/proxy state:** active VPN adapters, tunnel up/down, configured proxy vs. reachable proxy
- **USB/peripheral health:** USB device tree, recently connected/disconnected devices, driver errors per device — docks, webcams, USB printers, "my mouse stopped working"
- **Printers:** spooler queue, stuck jobs, default printer reachable, driver mismatch vs. print server
- **AD domain:** domain-joined?, secure channel OK?, last GPO apply time
- **BSOD/minidump:** see §8

New in v5 — the two collectors v4's triage profiles referenced but never defined:

- **Thermal & throttling:** sustained thermal throttling (not just an instantaneous temperature) — `thermald`/PROCHOT/package power limits on Linux, WMI thermal + `powercfg` on Windows, plus fan RPM where readable. v4's `slow` triage weighted `thermal_throttle` against nothing; this fills it.
- **Captive portal / link-layer reality:** captive portal detection (known-good HTTP 204 probe vs. redirect), DHCP lease state and age, duplicate-IP / ARP conflict, 802.1X / NAC authentication state. v4's `no-internet` triage weighted `captive_portal` against nothing; this fills it.

New in v5 — the collectors that matter most for the Belgian SMB/M365 market:

- **Azure AD / Intune / MDM state:** `dsregcmd /status` (Azure AD joined / hybrid / workplace-joined, PRT state), Intune sync status and last check-in, MDM enrolment health, GPO apply failures, Windows Hello for Business state. Single richest source of "I can't sign in / my policies aren't applying" tickets, and it demonstrates AD + Azure competence directly.
- **M365 client health:** Outlook OST size vs. limits, autodiscover reachability, cached credentials/token state, Teams cache size and health, OneDrive sync status and error state, SharePoint mapped-drive reachability. Enormous ticket volume in every M365 shop; nothing on the market interprets it.
- **Memory & hardware errors:** WHEA errors (Windows) / `mcelog`, EDAC counters, `ras-mc-ctl --summary` (Linux), plus last MemTest result if present. Corrected-error counts rising is the #2 cause of random crashes after disk, and it is *invisible* to every tool in §1.
- **Filesystem state:** NTFS dirty bit, pending chkdsk, ext4/xfs remount-read-only events, degraded LVM / mdadm RAID1 arrays, ZFS pool state, filesystem errors in dmesg, inode exhaustion (a full-inode disk shows 60% free space and behaves like a full disk — a classic "impossible" ticket)
- **Firmware & platform trust:** Secure Boot state, TPM presence/version/ownership, fwupd **HSI level** and available firmware updates (Linux), BitLocker/LUKS active + recovery key escrowed?, BIOS version vs. vendor latest, kernel taint state. Nobody in §1 ships an HSI-aware helpdesk view — this is a genuine differentiator and it comes straight out of the homelab work this spec grew from.
- **Boot analysis:** `systemd-analyze blame` + failed units (Linux), boot trace and Windows **fast-startup/hybrid-shutdown state** (Windows — this is why "I restarted it" often didn't restart it, and it explains an entire category of tickets), autostart/login-item bloat
- **Graphics & display:** GPU driver version, hybrid-graphics state (Nvidia/Intel — Optimus/PRIME offload sanity), external monitor + dock topology, VAAPI/DXVA hardware-acceleration availability, display driver crash/reset counts (TDR on Windows)
- **Audio/video devices:** camera and microphone present, enabled, and **held by which process**, driver state, default device sanity. Teams/Meet "nobody can hear me" is an endless ticket source and is currently answered by guesswork.
- **Power & dock:** charger wattage negotiated vs. required, dock firmware, USB-PD state, battery design vs. full-charge capacity, sleep/wake failure history — "it's slow only when docked" is a real and maddening ticket
- **Swap/pagefile:** pagefile/swap configured?, size, zram state, swap thrash indicators
- **Licensing/activation:** Windows activation and licence state, KMS reachability — cheap to collect, common, embarrassing to miss
- **Browser/profile:** PAC file reachable and valid, proxy auto-config vs. system proxy mismatch, extension count, enterprise root CA present (TLS-inspection appliances break the strangest things)

### 4.3 Output

One structured JSON/YAML blob — same shape regardless of OS, so everything downstream (interpreter, ticket attachment, diff, correlation) never needs to know which platform it came from.

**Versioned schema:** the blob carries `schema_version` from day one. Collectors and interpreter evolve independently; old snapshots stay readable forever. Cheap now, painful to retrofit.

**Per-collector envelope:** every section carries `status` (`ok` | `skipped` | `timeout` | `error`), `reason`, `duration_ms`, and `privilege_level` — this is what makes §3.4 ("absence is never health") mechanically enforceable rather than a good intention.

**Redaction layer:** before a snapshot leaves the machine, a redaction pass masks anything sensitive — usernames, hostnames (optional), public IPs, MAC addresses, SSIDs, serial numbers, ticket tokens.

- `--full` — everything, for internal ticket use
- `--anon` — redacted export, safe to paste into a public forum or send to a vendor
- **Redaction is tested like a security control, not a feature**: a fixture containing every known sensitive pattern must come out clean, and the test fails on any new schema field that has no redaction decision recorded for it. An unredacted field must be an explicit choice, never an oversight.

---

## 5. Data Governance & GDPR (new in v5)

A snapshot contains usernames, hostnames, internal network topology, installed software, serial numbers and sometimes certificate subjects. That is personal data and infrastructure intelligence in one file. Treating it casually would be indefensible in exactly the environments this tool is pitched at.

- **Purpose limitation:** a snapshot exists to resolve one ticket. It is attached to that ticket and nothing else.
- **Retention:** snapshots expire on a configurable schedule (default **90 days** after ticket closure), enforced by a `diag prune` job the Ops Console can schedule. Baselines are exempt but are re-taken, not accumulated — one current baseline per asset, plus at most N historical snapshots for the timeline (default 12).
- **Right to erasure:** `diag forget --asset <id>` removes every snapshot, baseline and timeline entry for a machine and records the deletion in the audit log. A support tool must be able to answer "delete everything you have about me."
- **Access:** snapshots inherit the ticket's ACL. If you cannot read the ticket, you cannot read the diagnostic.
- **Minimisation by default in transit:** `diag report --ticket` applies `--anon` unless `--full` is passed explicitly. The default direction of travel is *less data*.
- **Audit log:** who ran what against which asset, when, and which mode. Append-only, hash-chained (reusing the snapshot hashing from §12.7).
- **Documented data inventory:** one table in the repo listing every schema field, whether it is personal data, and its redaction rule. This is the artefact a DPO actually asks for, and it doubles as the redaction test's source of truth.

---

## 6. Part B — Interpreter

Takes the collector's output and a built-in **pattern knowledge base**, and produces plain-language findings instead of a raw dump.

```yaml
# pattern_kb/entries.yaml (a few examples)
- id: win_unexpected_shutdown
  match:
    log_contains: "Event ID 41"
    os: windows
  finding: "Unexpected shutdown/restart — check power supply, drivers, or overheating."
  severity: warning
  confidence: likely
  next_step: "Correlate with thermal and WHEA findings; check for a recent driver change."

- id: dns_resolution_failing
  match:
    log_contains: "unable to resolve host"
    os: linux
  finding: "DNS resolution failing — check /etc/resolv.conf and DNS server reachability."
  severity: critical
  confidence: certain

- id: disk_free_critical
  match:
    disk_free_percent_below: 10
  finding: "Disk space critically low — may cause update failures, log rotation issues, or app crashes."
  severity: critical
  confidence: certain

- id: smart_reallocated
  match:
    smart_reallocated_sectors_above: 0
  finding: "Disk reporting reallocated sectors — early sign of drive failure. Back up now, plan replacement."
  severity: critical
  confidence: certain

- id: patch_lag
  match:
    updates_pending_above: 20
    days_since_last_check_above: 30
  finding: "System significantly behind on patches — increases exploit risk, consider scheduling maintenance."
  severity: warning
  confidence: certain
```

- Pattern matching starts simple (string contains / threshold rules) — no ML needed for v1, just an if-this-then-that rule set that is easy to keep extending
- Every match produces **finding** (plain language), **severity**, **confidence** (§3.5) and **suggested next step**
- Findings with no KB match still show the raw log line, clearly separated — the tool degrades to "here is the raw data" rather than hiding anything
- **Rule precedence (new in v5):** when several rules match the same evidence, the interpreter applies, in order: (1) most specific match wins over general, (2) higher severity wins ties, (3) `certain` beats `likely` beats `possible`, (4) explicit `supersedes: [rule_id, …]` in the KB wins over all of it. Duplicate findings are merged, not stacked — three rules firing on one full disk must produce one line, not three.
- **Multilingual output (NL/FR/EN/DE):** findings live in the KB with translations per language; `--lang nl` renders the whole report in Dutch. Belgium has **three** official languages, so German is included — it costs one YAML file and it is the kind of detail that says the author actually knows the market. Pattern *matching* stays language-independent; only finding text is translated.
- **Locale-independent matching:** log lines on a Dutch-language Windows install do not read "Access denied". Matching keys on event IDs, error codes and numeric thresholds wherever possible, and where a string match is unavoidable, the rule carries the string per locale. This is the bug that would otherwise make the tool silently useless on exactly the machines it is built for.

### 6.1 Baseline & Diff Mode

The single most useful question in troubleshooting is *"what changed?"*:

- `diag baseline` — save the current snapshot as the known-good state for this machine
- `diag run --diff` — compare now vs. baseline and put the **differences first**: new failing services, new error types, disk usage delta, changed DNS servers, new listening ports
- `--since 3d` (new in v5) — anchor log and event analysis to a time window, because the first question a technician asks is "when did it start?". Works with `diag why` too: `diag why crashes --since 1w`
- Each asset in the Ops Console keeps a timeline of snapshots, so a ticket can show "this machine was healthy on Tuesday; here is exactly what is different today"

This turns the tool from a camera into a motion detector.

---

## 7. Symptom-Driven Triage

Real helpdesk starts from a **complaint**, not a machine. Triage mode flips the entry point:

```
diag why slow
diag why no-internet
diag why printing
diag why crashes
diag why battery
diag why meeting        # camera/mic/Teams — new in v5
diag why login          # AAD/Intune/GPO/clock/certs — new in v5
```

Each symptom maps to a **triage profile** in the KB: which collectors to run, at what depth, and which pattern subsets to weight highest:

```yaml
# pattern_kb/triage.yaml
- symptom: slow
  collectors: [system, boot_time, autostart, disk_io, top_processes, smart, wifi, thermal, memory_errors, swap]
  deep: { boot_time: true }
  weight: [disk_free_critical, smart_*, autostart_bloat, wifi_weak, thermal_throttle, swap_thrash]
  ask:
    - q: "Slow all the time, or only when docked?"
      options: [always, docked]
      docked: { collectors: +[power_dock, graphics] }

- symptom: no-internet
  collectors: [network, wifi, vpn_proxy, clock, certificates, captive_portal]
  weight: [dns_*, gateway_unreachable, vpn_half_up, proxy_stale, captive_portal_detected, dhcp_lease_stale, ip_conflict]
  ask:
    - q: "Wired or Wi-Fi?"
      options: [wired, wifi]
      wired: { collectors: -[wifi] }

- symptom: login
  collectors: [ad_domain, aad_intune, clock, certificates, network]
  weight: [clock_drift, aad_prt_invalid, secure_channel_broken, cert_expired, gpo_apply_failed]
```

- Runs in a fraction of the time of a full sweep, and leads with findings *relevant to the complaint*
- **Interactive pruning (new in v5):** a profile may declare `ask` — at most **two** questions, each one binary, each one measurably changing which collectors run. "Wired or Wi-Fi?" removes an entire branch in one keystroke. `--yes`/`--no-ask` skips them for scripted runs, falling back to the full profile.
- Unknown symptom → falls back to a full `diag run` (same graceful-degradation principle as unmatched log lines)
- `diag simple` gains the same flag: tell the end user "type `diag why slow`" and read back the traffic-light card — complaint in, colours out
- Triage profiles are KB entries, so the close-ticket "learn a pattern" flow can grow the *triage* mapping too: this ticket was symptom X, root cause was Y → strengthen that link

This is the structural difference between a diagnostic *dump* tool and a diagnostic *companion*: it starts where the ticket starts.

---

## 8. Fleet Correlation — "it's not the machine, it's the server"

Six machines reporting the same DNS failure at 09:02 means the **DNS server** is broken — not six client machines.

- `diag fleet --correlate` groups identical finding IDs appearing on N+ assets within a time window
- Output leads with the environment-level conclusion: *"6 of 9 assets report `dns_resolution_failing` since 09:02 — shared cause likely upstream (DNS server / gateway / DHCP scope). Open ONE ticket, not six."*
- The Ops Console hook respects this: correlated findings create a single environment ticket listing affected assets, instead of an alert storm
- Correlation rules live in the KB: same SSID + many `wifi_weak` → access point issue; many `clock_drift` → NTP source issue; many `aad_prt_invalid` → federation/token service issue
- **Correlation needs a denominator:** "6 assets" is meaningless without "of 9 checked". Every correlated finding reports affected/checked, and assets whose relevant collector was skipped are excluded from both numbers rather than counted as healthy

No agent, no monitoring stack — just reading snapshots you already have.

---

## 9. Policy & Compliance Baseline

Per-machine baseline answers *"what changed on this box?"*. A **policy file** answers *"does every box meet our rules?"* — declarative, fleet-wide, versioned in git:

```yaml
# policy/kmo-default.yaml
- rule: firewall_enabled          # UFW / Windows Firewall on
  severity: critical
- rule: disk_encrypted            # LUKS / BitLocker active
  severity: critical
- rule: recovery_key_escrowed     # new in v5 — encrypted but unrecoverable is a disaster, not compliance
  severity: critical
- rule: secure_boot_enabled       # new in v5
  severity: warning
- rule: av_scan_max_age_days: 7
  severity: warning
- rule: updates_max_pending: 30
  severity: warning
- rule: os_supported              # not past end-of-life
  severity: critical
```

- `diag policy check` evaluates any snapshot (or the whole fleet) against the policy and reports pass/fail per rule, per machine
- **`unknown` is a third outcome, not a pass** — a rule whose collector was skipped reports `unknown` and is listed separately. A compliance report that turns "I couldn't check" into "compliant" is worse than no report.
- Exit codes work like `diag run`, so compliance can gate onboarding scripts or run on a schedule via `diag watch`
- The HTML report gains a compliance tab: one page a manager reads, one file to hand an auditor
- Multiple policy files (`laptops.yaml` adds battery + Wi-Fi rules; `servers.yaml` adds listening-port allowlists)

This is a different *question* than diff mode, and it is the feature managers ask about first.

---

## 10. Windows Error-Code Decoder

The most cryptic strings an end user will ever paste into a ticket are a BSOD stop code and a Windows Update failure code. Both fit the existing KB format.

- **BSOD minidump summary:** parse the latest minidumps (WhoCrashed-style) and report *which driver faulted*, how many times, and since when — "`nvlddmkm.sys` faulted 3× this week → GPU driver issue, roll back or update" instead of a hex wall
- **Windows Update decoder:** failure codes → plain language + next step — `0x80070005` → *"Access denied — usually antivirus interference or permissions; try SFC then a clean-boot update"*; `0x8007000E` → *"Out of memory/disk during update — check free space first"*
- Both are pure pattern entries: no new engine, translations come free via the NL/FR/EN/DE layer, and every decoded code ships with a fixture

Cheap to build, huge perceived magic — the "how did it know that?" moment for Windows-heavy environments.

---

## 11. User-Initiated Push — `diag report --ticket 123`

The missing direction is **machine→Console**: the user runs one command and the snapshot delivers itself.

- `diag report --ticket 123` runs the collectors and POSTs the snapshot onto an existing ticket via the Ops Console API — no file transfer, no screen sharing, no "can you email me that file?"
- `diag report --new "printer broken"` creates the ticket *and* attaches the diagnostic — the ticket is born pre-diagnosed
- Works from home networks and machines the Console cannot reach inbound — covers remote workers, the fastest-growing blind spot of the SSH/WinRM model
- Auth via a short-lived ticket token printed in the ticket itself (read over the phone, like the support code in reverse); `--anon` redaction applies before anything leaves the machine, and is the **default** here (§5)
- No connectivity? The same command falls back to writing the snapshot + a QR/support-code summary locally, closing the loop with the offline story

---

## 12. Knowledge Base Governance (new in v5)

"Prompt to add a pattern on every ticket close" is the feature that makes this tool *yours* — and, unmanaged, it is the feature that ruins it. Within a year the KB fills with rules overfitted to one machine on one bad Tuesday, and the tool becomes confidently wrong. The KB therefore needs the same discipline as code.

### 12.1 Provenance

Every rule records where it came from:

```yaml
- id: log_growth_abnormal
  provenance:
    source: ticket        # seed | ticket | vendor_kb | manual
    ticket_id: 4711
    author: popeye-mk
    created: 2026-07-18
    reviewed_by: null
  stats:
    fired: 0
    confirmed: 0
    false_positive: 0
```

A rule with `source: ticket` and no review enters the KB in **quarantine**: it fires, but its findings render in the "worth checking" section only, never the headline, until a human promotes it.

### 12.2 Feedback loop

Closing a ticket asks one extra question: *"Did the top finding actually name the cause?"* — yes/no/partly. That single click maintains `stats` for the rule that fired.

- `confirmed / fired` is the rule's **hit rate**, shown in every KB listing
- A rule below 50% hit rate after 10 firings is auto-demoted to `possible` confidence and flagged for review
- A rule that has never fired in 12 months is flagged as dead weight
- **This is also the honest answer to "how do you know your tool is right?"** — an interviewer will ask, and "I measure it" is a much better answer than "it's a good rule set"

### 12.3 `diag kb lint`

A pre-commit check over the rule set:

- Every rule has an `id`, `severity`, `confidence`, `next_step` and at least one fixture that makes it fire
- No duplicate IDs; no unreachable rules (fully shadowed by a more general rule); no circular `supersedes`
- Every finding has translations for all four languages, or an explicit `translation_todo` marker
- Every threshold has a unit and a comment saying where the number came from — "disk_free < 10%" is a judgement, not a law of nature
- Every referenced collector exists (this is precisely the check that would have caught v4's `thermal_throttle` and `captive_portal` weights pointing at nothing)

### 12.4 Distribution and versioning

- The KB is a git repo, versioned independently of the binary, with a `kb_version` recorded in every report — so a finding can always be traced back to the exact rule text that produced it
- `diag kb update` pulls a **signed** bundle; a KB is executable-adjacent (it tells technicians what to do, and `fix` blocks tell the tool what to run), so an unsigned KB update channel would be a supply-chain hole
- Local rules live in `pattern_kb/local/` and always win over shipped rules, so an update never silently overwrites site knowledge
- Shipped seed rules are curated; ticket-learned rules stay local unless explicitly promoted and reviewed

### 12.5 Rule review

Ticket-learned rules are reviewed like pull requests: `diag kb review` lists quarantined rules with their firing history and the ticket they came from, and promotion is a deliberate act. Ten seconds per rule, once a month, is the difference between a knowledge base and a landfill.

---

## 13. Security & Threat Model (new in v5)

This tool runs as root/Administrator on many machines, reads their most sensitive state, and can POST it to an API. It is exactly the sort of thing an attacker wants to own. Ignoring that in the spec would undercut every security-conscious pitch made elsewhere in it.

**Assets:** snapshot contents (personal data + infrastructure map), the ticket token, the KB (which can carry `fix` commands), the binary itself.

| Threat | Mitigation |
|---|---|
| **Malicious/spoofed Console endpoint** harvesting snapshots | Console URL is pinned in config, TLS with certificate pinning, endpoint identity verified before any data is sent. `--anon` by default on push (§5). |
| **Ticket token theft / replay** | Tokens are single-use, scoped to one ticket, short-lived (15 min), and bound to the asset ID. A leaked token buys one upload to a ticket the holder already knew about. |
| **Poisoned KB** — a rule with a hostile `fix` command | KB bundles are signed; `fix` blocks are **whitelisted commands only**, never free-form shell; `risk: low` is required for auto-suggestion; `--apply` always needs explicit per-fix confirmation. Local KB rules with `fix` blocks cannot be introduced by `kb update`. |
| **Tampered binary** on a USB stick | Signed releases (Authenticode on Windows, minisign/GPG + reproducible builds elsewhere), published hashes, and `diag verify --self`. |
| **Snapshot tampering** to hide evidence | SHA-256 per snapshot recorded at attach time; `diag verify snapshot.json` (§14.7); audit log hash-chained. |
| **Privilege escalation via the tool** | No setuid, no service, no daemon. It is a short-lived process the operator elevates deliberately. Subprocess calls use absolute paths with no shell interpolation of collected data. |
| **Untrusted collector output as an injection vector** | Everything collected is treated as hostile input: no eval, no shell, strict schema validation, output escaped before HTML rendering. A hostname is attacker-controllable on a compromised box. |
| **`custom/` collector plugins** running arbitrary code | Documented as a trust boundary: a custom collector runs with the tool's privileges. They are never loaded from a snapshot, never fetched over the network, and are off unless explicitly configured. |

### 13.1 The AV problem (the actual showstopper)

An unsigned PyInstaller binary that reads event logs, SMART data, minidumps and the certificate store, then makes network calls, is a near-perfect description of malware. Defender, SmartScreen and half the endpoint products in Belgium **will** quarantine it, and "run this .exe I made" is already the hardest sell in support work. This must be designed for, not discovered:

- **Code signing from v1.** An OV certificate is the minimum; without it SmartScreen blocks the download and the demo dies in front of the client.
- **Reputation takes time** — signed builds accumulate SmartScreen reputation only through downloads, so the signing certificate must exist before it is needed, not the week of the interview.
- **Prefer the script path where possible:** ship a signed PowerShell module / Python package as the primary channel for managed environments (they can allowlist by publisher), with the single binary as the "stranger's broken PC" fallback.
- **Reduce the malware silhouette:** no packing/obfuscation, no in-memory unpacking tricks, no runtime downloads, no self-modification, no network egress on a default run (§3.6). PyInstaller's unpack-to-temp behaviour is itself a heuristic trigger — evaluate a zipapp or Nuitka build and test all three against Defender before committing.
- **Test it like a feature:** every release candidate is scanned (VirusTotal + a real Defender-enabled VM) and false positives are submitted to Microsoft's analyst portal. The KVM lab already exists for exactly this.
- **Document the hash and signature** in the README so a suspicious admin can verify rather than refuse.

---

## 14. Wow-Factor Features

Each is demoable in under a minute, none requires ML or cloud services, and together they hit three audiences: the **end user** (simple mode, HTML report), the **technician** (chains, fix mode, decode), and the **manager/employer** (fleet board, policy, demo mode, verifiable evidence).

### 14.1 Root-cause chains — findings that explain each other

A flat list of findings is good; a *story* is better. A second pass links matched findings with `implies`/`caused_by` relations:

```yaml
- chain:
    when: [disk_free_critical, log_growth_abnormal, service_crash]
    story: "Runaway log growth (/var/log +38 GB in 6 days) filled the disk to 4%,
            which crashed the nginx service. Fix the log rotation and the other
            two findings resolve themselves."
    root: log_growth_abnormal
    confidence: likely
```

The report leads with **one root cause** instead of three symptoms — it mirrors exactly how a good technician thinks. A chain never fires on `possible`-confidence members, and when a chain's evidence is incomplete it degrades to the flat finding list rather than inventing a narrative.

### 14.2 `diag simple` — end-user mode ("read me the colours")

A traffic-light card: a handful of big lines, no jargon, in the user's language:

```
[OK]     Internet connection      OK
[FAIL]   Disk space               Almost full — this is likely your problem
[WARN]   Windows updates          32 pending
[OK]     Antivirus                Active, scanned yesterday
[?]      Disk health              Could not check (needs administrator)
Support code: DC-7F3A
```

- **Accessible by construction (new in v5):** never colour alone. Every line carries a text label (`OK` / `WARN` / `FAIL` / `?`) and a shape, so it survives colour-blindness, a screen reader, a monochrome print, and a phone photo of a screen — which is how these actually reach a technician.
- **No emoji in terminal output (new in v5):** Windows consoles (and every SSH session through a legacy terminal) mangle them, and "my screen shows a black diamond with a question mark" is not the ticket you want. Emoji are permitted in the HTML report only, alongside the text label.
- **Support code:** encodes the finding IDs plus KB version. The user reads 6 characters over the phone; the technician types `diag decode DC-7F3A` and sees the full findings without any file transfer. Codes are checksummed (so a misread is rejected, not misinterpreted), namespaced to avoid collisions, and expire with the snapshot.

This turns a 15-minute "what does your screen say?" call into 30 seconds.

### 14.3 `diag fix` — safe guided remediation (dry-run first, always)

KB entries can carry an optional, whitelisted `fix` block:

```yaml
  fix:
    linux:  "journalctl --vacuum-size=500M"
    windows: "Clear-RecycleBin -Force; cleanmgr /sagerun:1"
    risk: low
    reversible: false
```

- `diag fix --dry-run` (the default) shows exactly what would run and why — never executes
- `diag fix --apply` runs only after explicit per-fix confirmation, then re-runs the relevant collector to **prove the fix worked** ("Disk free: 4% → 31% ✓") and logs before/after into the ticket
- Only `risk: low` fixes are ever auto-suggestible; anything else stays advice-only
- Commands come from a **whitelist**, never free-form shell, and never with collected data interpolated into them (§13)
- `--apply` is refused entirely when the KB rule is quarantined or below its hit-rate threshold (§12.2). The tool does not act on knowledge it has not yet earned.

The before → action → verified-after loop in one command closes the ticket *with evidence*.

### 14.4 One-file interactive HTML report

`--format html` produces a **single self-contained .html** (inline CSS/JS, zero dependencies, works from a USB stick offline): findings ranked by severity with expandable raw evidence, the baseline diff as a visual timeline, sparklines for disk/CPU history across snapshots, a compliance tab, a "Not checked" section, and a language toggle (NL/FR/EN/DE) in the page itself. One file serves the technician *and* the end user *and* the manager. All collected values are HTML-escaped (§13). Email it, attach it to a ticket, open it in five years — it still works.

### 14.5 `diag demo` — the interview weapon

`diag demo dying-disk` replays a canned scenario end-to-end — collector output, root-cause chain, simple-mode card, HTML report, ticket hook against a mock endpoint — on any machine, in 20 seconds, zero setup, zero risk. It exists so the whole product can be shown live in a job interview or to a prospective client without a conveniently broken PC nearby. The fixtures already exist for testing; this gives them a front door.

### 14.6 Fleet health board — "which machine dies next?"

`diag fleet` reads the latest snapshot of every registered asset and renders one ranked table: health score, top finding, days since baseline, trend arrow. Sort by "most likely to generate a ticket this week." For a small KMO this is a poor-man's monitoring dashboard with zero agents and zero infrastructure.

- Health score is **explainable by construction**: 100 minus weighted deductions per finding, with every deduction listed. No black box, so it is defensible when a manager asks "why is this machine a 61?"
- A machine with skipped collectors shows its score with a coverage indicator (`61 · 7/11 checked`), never a confident number over missing data (§3.4)

### 14.7 Tamper-evident snapshots

Every snapshot gets a SHA-256 recorded in the ticket at attach time; `diag verify snapshot.json` re-checks it. Ten lines of code, and it means a diagnostic attached to a ticket is *evidence*, not just a note — relevant the moment the tool touches anything compliance-adjacent.

---

## 15. The Combination (rewritten, defensible)

Not "nobody has ever done any of this" — several tools do pieces of it well. The claim is that nothing packages these together, and that the package is what a small IT department actually needs:

1. **Interpretation, not just collection** — osquery gives you a schema; this gives you a finding, a severity, a confidence and a next step. In the user's language.
2. **Zero agent, zero server, zero enrolment** — one signed binary. RMM tools cannot touch a machine that was never enrolled, and neither can they touch one that will not boot.
3. **Works on a dead machine** — the Ventoy live entry reads disks, SMART and logs from an install that cannot start itself. Every agent-based tool in §1 misses this case entirely.
4. **Causal grouping** — root-cause chains collapse three symptoms into one cause; fleet correlation collapses six machines into one upstream ticket. Threshold alerting does the opposite.
5. **A KB that learns your environment** — and governs itself (§12), so it stays trustworthy instead of rotting.
6. **Starts at the complaint** — `diag why slow` mirrors how tickets arrive.
7. **Answers "what changed?"** — baseline + diff, where the root cause almost always lives.
8. **Answers the manager too** — policy compliance in one page, one file for an auditor.
9. **Speaks NL/FR/EN/DE** — the same diagnostic is readable by technician, end user and manager, in Belgium's three official languages.
10. **Reaches machines the Console cannot** — user-initiated push from any home network, one command.
11. **Honest about its own limits** — every report says what it could not check and how confident it is. That is rarer in this market than any feature above.

---

## 16. Scriptable & Monitorable

- **Exit codes:** `0` healthy, `1` warnings, `2` critical findings — so cron or the Ops Console health checker reacts to the diagnosis, not just "did it run". Only `certain`-confidence findings can produce `2` (§3.5). A run with skipped collectors and no findings exits `0` but sets `coverage_incomplete` in the JSON.
- **`--format json|yaml|html|md`** — machine-readable for pipelines, HTML for tickets/email, Markdown for pasting anywhere
- **`diag watch --interval 6h`** — scheduled runs that only create a ticket when the finding set *changes* — no alert spam for a known, already-ticketed issue

---

## 17. Extensible Collectors

Collectors are small plugins, each writing one section of the shared schema, each declaring its timeout, required privilege level and applicability:

```
collectors/
├── core/          # network, system, logs, services — always run
├── optional/      # auto-skip when not applicable
└── custom/        # drop-in scripts; anything printing valid schema JSON is a collector (trust boundary — see §13)
```

Each collector declares a manifest, which is what makes `kb lint`, the privilege table and the "Not checked" section possible:

```yaml
# collectors/optional/smart/manifest.yaml
id: smart
privilege: elevated
timeout_s: 30
applies_when: { has_physical_disk: true }
os: [linux, windows]
on_timeout_finding: smart_read_timeout
```

---

## 18. Project Structure

```
diagnostic-companion/
├── collectors/
│   ├── core/                     # network, system, logs, services
│   ├── optional/                 # smart, battery, wifi, thermal, printers, ad_domain, aad_intune,
│   │                             # m365_client, clock, certificates, vpn_proxy, captive_portal, usb,
│   │                             # bsod, memory_errors, filesystem, firmware_trust, boot_analysis,
│   │                             # graphics, av_devices, power_dock, swap, licensing, browser_profile
│   └── custom/                   # user-supplied plugins
├── interpreter.py                # loads pattern_kb, matches, resolves precedence, assigns confidence
├── pattern_kb/
│   ├── entries.yaml              # the growing rule set
│   ├── triage.yaml               # symptom → collectors/weights/questions (diag why …)
│   ├── correlation.yaml          # shared-cause rules for fleet correlation
│   ├── chains.yaml               # root-cause chain definitions
│   ├── winerrors.yaml            # BSOD stop codes + Windows Update decoder
│   ├── local/                    # site-specific + ticket-learned rules (always win)
│   └── lang/                     # nl.yaml, fr.yaml, en.yaml, de.yaml
├── policy/
│   └── kmo-default.yaml          # declarative compliance rules (diag policy check)
├── report.py                     # terminal + HTML + Markdown rendering (escaping, a11y labels)
├── redact.py                     # --anon masking (+ data inventory as source of truth)
├── diffing.py                    # baseline storage + snapshot comparison
├── correlate.py                  # cross-asset finding correlation
├── kb_tools.py                   # diag kb lint / review / update / stats
├── govern.py                     # retention, prune, forget, audit log
├── ticket_hook.py                # Console-pull and user-push, pinned TLS, token handling
├── ventoy_boot/
│   └── diagnostic-live.iso       # minimal live Linux entry for unbootable machines
├── docs/
│   ├── DATA_INVENTORY.md         # every schema field: personal data? redaction rule?
│   ├── THREAT_MODEL.md
│   └── PRIVILEGES.md
├── tests/
│   ├── fixtures/                 # canned collector JSONs (healthy, dying-disk, dns-broken, …)
│   ├── golden/                   # real collector output captured from the KVM lab
│   └── chaos/                    # truncated, malformed, hostile snapshots
└── cli.py                        # diag run / why / baseline / diff / simple / decode / fix / fleet /
                                  # policy / report / watch / demo / verify / kb / prune / forget
```

---

## 19. Testing

v4 tested the interpreter only. That is the easy half.

- **Interpreter tests (fixtures):** canned collector outputs for known scenarios. Fast, deterministic, no VM. **Every new KB rule ships with a fixture that proves it fires** — enforced by `kb lint`.
- **Collector golden tests (new):** real output captured from the KVM lab (Zorin, Ubuntu 26.04, Windows 11, macOS Sonoma via OSX-KVM) and committed as golden files. A collector change that alters output shape fails the build. The lab already exists; this is free coverage.
- **Schema conformance (new):** every collector's output validates against the versioned schema, on every OS, every run. Property-based tests for the envelope fields.
- **Redaction tests (new):** a fixture seeded with every sensitive pattern must come out clean under `--anon`; the test fails if a schema field exists with no redaction decision in `DATA_INVENTORY.md`.
- **Read-only assertion (new):** collector runs against a snapshotted filesystem must produce zero mutations outside the output path (§3.2).
- **Chaos fixtures (new):** truncated JSON, wrong schema version, a hostname containing `<script>`, a 2 GB log section, a SMART tool that never returns. None may crash the interpreter; all must degrade to a readable report.
- **Locale tests (new):** the same scenario on a Dutch-language Windows install must produce the same findings as on English (§6). This is the bug that quietly kills the tool in its target market.
- **AV/reputation check (new):** every release candidate scanned against Defender in a VM and VirusTotal, false positives reported (§13.1).

---

## 20. Packaging & Distribution

- **Single self-contained binary** (evaluate zipapp / PyInstaller / Nuitka against AV heuristics before choosing) so it runs on a client machine with no Python — critical for the "run it on a stranger's broken PC" case
- **Signed** on every platform, from v1, for the reasons in §13.1
- **Signed PowerShell module / pip package** as the primary channel for managed environments that allowlist by publisher
- **Published hashes + `diag verify --self`**
- **Reproducible builds** where achievable — it costs little and it is a strong signal for a security-conscious employer
- **Licence: MIT** for the tool. It is a portfolio piece whose job is to be read, run and reused by a prospective employer without a legal conversation; AGPL would protect a business model that does not exist yet and add friction exactly where the value is. The `pattern_kb/local/` contents stay private by default and are excluded from the repo — the *rules of your environment* are not portfolio material.

---

## 21. Example Flow

1. Ops Console flags `web-02` as `down` after 3 failed checks → auto-creates a ticket
2. Ticket creation triggers `ticket_hook.py`, which runs the collector against `web-02` (if reachable) or prompts "attach diagnostic from Ventoy boot" if not
3. Interpreter produces: *"Disk free space at 4% — likely cause of service crash. Suggested: clear `/var/log`, expand disk, or investigate log rotation config."* Diff mode adds: *"Changed since baseline: `/var/log` grew 38 GB in 6 days."* The report footer notes: *"Not checked: SMART (insufficient privileges)."*
4. The finding is embedded at the top of the ticket, hash recorded, full raw report attached below
5. `diag fix --dry-run` shows `journalctl --vacuum-size=500M`; after confirmation, `--apply` runs it and re-checks: *"Disk free: 4% → 31% ✓"*
6. Closing the ticket asks two questions: *"Did the top finding name the cause?"* (maintains the rule's hit rate) and *"Save this as a known pattern?"* → the new rule enters quarantine with its ticket provenance, and appears in the next `diag kb review`

---

## 22. Roadmap

**v1 — standalone CLI (useful on day one)**
Core collectors (both OSes) → interpreter with ~12 seed rules from real homelab issues → terminal + Markdown report → fixtures-based tests → **signed** single-binary packaging → NFR skeleton: per-collector timeouts, privilege tiers, "Not checked" section, read-only assertion test.

**v1.1 — the "what changed?" release**
Baseline/diff, `--since`, exit codes + `--format`, redaction/`--anon` + `DATA_INVENTORY.md`, SMART + battery + Wi-Fi + clock + thermal collectors, `diag demo` (cheapest wow first).

**v1.2 — Belgian polish**
NL/FR/EN/DE output + locale-independent matching, printers + AD domain + VPN/proxy + certificates + captive_portal + USB collectors, Windows error-code decoder, single-file interactive HTML report, `diag simple` + support codes (accessible, no emoji in terminal).

**v1.3 — the complaint-driven release**
Symptom triage (`diag why …`) with the first profiles (slow, no-internet, printing, crashes, battery, meeting, login) + interactive pruning questions.

**v1.4 — the M365 release (new in v5)**
`aad_intune` + `m365_client` + `graphics` + `av_devices` collectors. The highest-ticket-volume area in the target market, and the clearest demonstration of AD/M365/Azure competence.

**v2 — Ops Console integration**
`ticket_hook.py` (Console-pull), user push (`diag report --ticket/--new`) with pinned TLS + scoped tokens, snapshot timeline per asset, close-ticket "learn a pattern" + hit-rate feedback, `diag watch`, Ventoy live entry, snapshot hashing/`diag verify`, retention/`prune`/`forget` + audit log.

**v2.1 — the technician's release**
Root-cause chains, `diag fix --dry-run/--apply` with verified before/after, `diag fleet` health board with coverage indicators.

**v2.2 — the environment release**
Fleet correlation with denominators and one-environment-ticket behaviour, policy/compliance mode + compliance tab, `recovery_key_escrowed` / `secure_boot_enabled` rules.

**v2.3 — the trustworthy-KB release (new in v5)**
Rule provenance + quarantine, `diag kb lint / review / stats`, signed KB bundles, hit-rate-driven demotion.

**Later / nice-to-have**
- `memory_errors`, `filesystem`, `firmware_trust`, `boot_analysis`, `power_dock`, `swap`, `licensing`, `browser_profile` collectors as ticket volume justifies each
- macOS collector (the schema already does not care — and the OSX-KVM VM is a free test bench)
- Optional local-LLM summariser for unmatched log lines (an **Anora** skill is a natural fit: feed it the "unrecognised" section, get a *draft* KB rule back — it enters quarantine like any ticket-learned rule and a human promotes it. The LLM never writes to the KB directly and never touches `fix` blocks.)
- Import adapters: read an osquery result set or a vendor dump and interpret it — turning the closest competitor into an input rather than a rival

---

## 23. Changelog — v4 → v5

**Positioning**
- Comparison table rewritten to include osquery, TacticalRMM/NinjaOne/GLPI, Sysinternals and vendor tools; "true cross-platform parity" downgraded from a novelty claim to a table stake; the moat restated as interpretation + zero-agent + offline + causal grouping + self-growing KB
- §15 rewritten to be defensible rather than absolute

**New sections**
- §3 Constraints & Non-Functional Requirements — privilege tiers, read-only guarantee, timeouts/partial results, "absence is never health", confidence levels, performance budget
- §5 Data Governance & GDPR — retention, erasure, access, audit log, data inventory
- §12 KB Governance — provenance, quarantine, hit-rate feedback, `kb lint`, signed distribution, review flow
- §13 Security & Threat Model — including §13.1, the AV/code-signing showstopper

**Fixed inconsistencies**
- `thermal_throttle` and `captive_portal` were weighted in v4's triage profiles but had no collectors; both now exist (and `kb lint` prevents a recurrence)
- Locale-dependent string matching would have broken the tool on Dutch/French Windows installs
- Emoji in terminal output; colour-only status in `diag simple`

**New collectors**
`thermal`, `captive_portal`, `aad_intune`, `m365_client`, `memory_errors`, `filesystem`, `firmware_trust`, `boot_analysis`, `graphics`, `av_devices`, `power_dock`, `swap`, `licensing`, `browser_profile`

**Smaller additions**
`--since` time windows; interactive triage pruning; `diag why meeting` / `why login`; German as the fourth language; rule precedence and finding de-duplication; correlation denominators; `unknown` as a policy outcome; coverage indicators on health scores; support-code checksums; MIT licence; expanded testing (golden, schema, redaction, chaos, locale, AV)
