# netdiag v1.5 — status against spec v2.3 §18 (v1 → v1.5)

Honest ledger: what this build ships, what is partial, what remains.
("Absence is never health" applies to roadmaps too.)

## Done in this build — network hygiene (§12) and discovery (§4.2/§11)

- **`hygiene` collector, both OSes:** the name-resolution poisoning surface
  (LLMNR / NetBIOS-NS / mDNS — the Responder attack, and all three are ON by
  default on Windows), SMBv1 state, RDP Network Level Authentication, and
  listeners on ports worth a second look (Telnet, FTP, TFTP, SNMP, VNC,
  RDP, databases, SMB). Four new rules; KB now 51.
- **Deliberately narrow claims:** an open port is "worth confirming you meant
  it", never "you are compromised"; 22/443 are not flagged at all; an
  unreadable setting stays ABSENT rather than becoming a false. All local
  reads — nothing is probed.
- **`netdiag devices`:** passive by default — the neighbour/ARP table this
  machine already has, with OUI vendor identification, gateway/self marked,
  randomised MACs explained rather than treated as suspicious. It states its
  own limit loudly: this is what this machine has SPOKEN TO, not an inventory.
- **The active sweep is gated (§3):** `-authorized` plus a typed `yes`, an
  explicit statement that it contacts OTHER people's machines, refusal of
  anything larger than ~/22 or any IPv6 range, a 1024-host cap, and bounded
  concurrency. It pings; it does not port-scan or fingerprint (§14 line).
- **`-save` / `-since`:** snapshot the network, compare later, get "NEW since
  <date>" by vendor — the shadow-IT question answered mechanically.
- Unit-tested: vendor lookup incl. dash/uppercase MACs and refusal to guess,
  locally-administered detection, incomplete-ARP filtering, role marking,
  arrival detection, /8 and IPv6 sweep refusals, /24 host maths, cancellation,
  and that the authorization text actually names what it does.

## Done in this build — speed and bufferbloat (§10)

- **`netdiag speed`** (menu: "Test speed and call quality"): measures idle
  latency, then saturates the link and measures latency AGAIN during the
  transfer. Reports the delta as an A–F grade on the DSLReports scale plus
  delivered throughput, and — with `-contracted 200` — delivered vs paid.
- **This is the one tier that is not free**, so it is fenced accordingly: a
  separate verb (never part of a scan), an explicit statement of the data
  cost BEFORE anything runs, a y/N consent prompt (`-yes` for scripts), a
  hard byte ceiling, and Ctrl-C that still reports what was measured.
- **The verdict names the fix**, not just the number: an F says "enable
  SQM/fq_codel on the router", because "grade F" alone is a measurement,
  not a diagnosis. Under-delivery against contract is phrased for the ISP
  conversation, and 80–100% of contract is explicitly NOT called a fault.
- **Honest limits printed every time**: measured over Wi-Fi (radio may be
  the ceiling, retest on cable), too few samples, run truncated, other
  traffic on the network. A throughput number without its caveats is a
  rumour.
- Unit-tested: grade boundaries, median-resists-outliers, Mbps maths,
  verdict wording, and the two failure modes that matter — no samples must
  be an error rather than an invented "A", and a cancelled run must keep
  the evidence it already had.

## Done in an earlier build — the v1.3 time-domain release (§9, §18 v1.3)

- **`netdiag watch -duration 2h -interval 5s`:** the motion camera to the
  rest of the tool's photograph. Bounded run (never a daemon — §14 draws
  that line), sampling the cheap passive facts and printing each
  interpreted event the moment it fires. Ctrl-C ends early and still
  prints the summary: an interrupted watch must not lose its evidence.
- **Events, not graphs:** link drops and recoveries, gateway-MAC change
  (ARP-spoof/failover signal), address / gateway / DHCP-server changes,
  Wi-Fi roams and RSSI collapses, loss episodes (opened once, closed once,
  carrying their peak), latency and DNS-slowness spikes, DNS failure while
  the link stays up.
- **Baseline-aware (§5.2):** "loss spiked to 22%" is judged against what is
  normal AT THIS LOCATION; with no baseline it says so and falls back to
  absolute thresholds.
- **Periodicity detection:** repeated events are grouped and their rhythm
  reported only when the gaps are actually regular (CV < 25%) — over-claiming
  a cycle sends a technician hunting a scheduled job that doesn't exist, so
  irregular recurrence is explicitly not called periodic.
- **Standing vs intermittent:** a fault already present at the first sample
  is reported as a standing fault and NOT as "the intermittent was caught"
  (found by the very first live smoke run). DNS is not blamed while the link
  is down — a consequence is not a finding.
- **Honest ledger inside the run:** per-metric min/median/max, plus what was
  unmeasured on how many ticks, and a verdict that refuses to call a quiet
  window proof of health.
- Tests: 11 unit tests over the event/periodicity logic (no network needed)
  + 5 namespace harness scenarios (terminates, standing-fault wording,
  unmeasured admission, catches loss, blames the local side).

## Done in this build — the local half of `cant-print` (§6.1)

`print_spooler` collector (Windows): service state judged by the numeric
`sc query` state (locale-proof), queue depth, errored jobs, jobs stale >15
min, default printer port. Two new L7 checks run BEFORE the transport probes
in the cant-print walk, three new rules (`print_spooler_stopped`,
`print_queue_jammed`, `print_queue_stale`) — because half of "I can't print"
never leaves the machine, and a tool that only probes 9100 blames the network
for a stopped spooler. KB now 46 rules.

## Done in this build — the v1.2 baseline release (§18 v1.2)

- **`netdiag baseline` (§5.2):** saves the passive snapshot as this
  location's known-good, keyed by gateway MAC with SSID/gateway-IP
  fallbacks — and saved under every candidate key, because the moment the
  gateway dies is exactly when its MAC fact vanishes and the baseline must
  still be findable (unit-tested).
- **`netdiag -diff`:** the motion detector — drift against this location's
  baseline: gateway-MAC change (ARP-spoof signal), DHCP-server change
  (rogue-DHCP signal), DNS/proxy/MTU/firewall-policy/802.1X changes, and
  numeric regressions against the location's own normal (loss +10 pts,
  latency ×2, DNS ×3, Wi-Fi −15 dB) — improvement is never drift, absence
  is never drift.
- **`netdiag compare good.json bad.json` (§7.1):** the same diff engine
  pointed at the working machine on the next desk. Interpreted, ranked
  delta ("start with #1"), plus the KB findings the broken machine has
  that the working one lacks; known-benign deltas (hostnames, this
  machine's MAC, timestamps, since-boot counters) deliberately ignored and
  listed as ignored; cross-OS comparison flagged honestly. Exit 1 on drift.
- Harness scenarios: two namespaces play good/bad machine, compare must
  produce the ranked delta (passing).

## Done in this build — the AD-lab deepening of `why cant-login` (§6.4)

- **"Against WHICH resolver":** SRV discovery now checks whether the
  configured resolvers are public (8.8.8.8-class → can never find a DC),
  queries each resolver directly when the system lookup fails, and calls
  out resolver-ORDER problems ("only some resolvers know the domain").
- **Fuller SRV walk:** DC-locator (_ldap._tcp.dc._msdcs) + _kerberos +
  _gc records; partial-zone detection.
- **Multi-DC:** all discovered DCs pinged (up to 3), `ad_dcs_responding`.
- **Clock vs the DC itself:** SNTP against the DC (w32time serves NTP) —
  Kerberos only cares about THAT offset; falls back to the generic one.
- **4 new rules** (43 total): `ad_dns_public_resolver` (the classic),
  `ad_dc_clock_skew`, `ad_secure_channel_broken`, `ad_dcs_unreachable` —
  tagged hardware-only; **AD_LAB_TESTING.md** is their reproduction
  script, keyed to the DC + Win 11 lab being built.
- Still remaining in §6.4: last GPO processing result (needs gpresult
  parsing on Windows).

## Done in earlier builds — the v1.1 triage release (§18 v1.1)

- **Blame-partition verdict (§8):** machine / LAN / ISP-WAN / destination
  table with ✓/✗/unknown per segment, confidence-gated, rendered as the
  headline of every scan and `why` run (and in `-json` and Markdown).
  A broken LAN makes the WAN *unknown*, not guilty; empty facts blame
  nothing.
- **`why` triage verbs (§6):** one layer-walk engine, eight profiles —
  `no-internet`, `slow`, `wifi`, `intermittent`, `cant-reach <host[:port]>`,
  `cant-print <printer>` (9100/IPP/LPD/SMB preset), `cant-rdp <host>`
  (3389 + NLA hint), `cant-login [domain]` (AD SRV discovery → DC ping →
  88/389/445/3268 → Kerberos clock tolerance → realm evidence). Target
  probes classify ports open/refused/filtered; unknown symptom falls back
  to a full scan. Findings are pruned to the symptom's layers.
- **`--for-user` (§6.2):** every embedded rule carries a jargon-free
  `for_user` template (enforced by unit test); rendered on request under
  scan and every `why` verb.
- **`feedback` verb (§5.3):** `netdiag feedback <rule-id> confirmed|wrong
  [--note]` → local append-only JSONL (`~/.netdiag/feedback.jsonl`,
  overridable via NETDIAG_FEEDBACK); bare `netdiag feedback` renders the
  per-rule confirmed/wrong rollup and flags >50% false-positive rules.
  Nothing is sent anywhere.
- **`-since <hours>`:** widens the event-history window.
- Harness grew verdict scenarios (`verdict_lan`, `verdict_isp`).

## Done in earlier builds — the v1 passive base

**Collectors (19 passive, Linux, stdlib-only):**
link (+ error/drop counters, carrier flaps), addressing (+ DHCP-lease
evidence), routing (+ multiple-default/metric-conflict, table size),
DNS config & resolution test, gateway ping, **neigh/ARP** (gateway MAC,
incomplete ratio), **sockets** (/proc/net/tcp*, listening/established/
time-wait), **net_quality** (loss/RTT/jitter windows to gateway + public
anchor, kernel path-MTU read), **tcp_stats** (retransmit ratio, resets,
attempt fails — per-netns kernel counters), **time_sync** (daemon detection
+ one SNTP exchange, measured clock offset), **dns_extra** (hosts-file
overrides, per-resolver direct queries + disagreement, public-name→private-IP
hijack check, Firefox-DoH heuristic), **ipv6** (global addr, v6 default
route, v6 path probe → broken-dual-stack), **captive_portal** (HTTP 204
probe, redirect = finding), **proxy** (env + reachability + WPAD),
**vpn** (tunnel adapters, full/split tunnel, debris), **wifi**
(/proc/net/wireless quality + signal), **nic_power** (runtime PM, USB NIC),
**event_history** (journalctl mining: link flaps / Wi-Fi drops / DHCP
failures over 24 h), **ad_state** (krb5/sssd/winbind join heuristics).

**Interpreter & KB:** 31 seed rules across L1–L7, each carrying a `repro`
tag (`namespace` / `netem` / `hardware-only`) per §16.1; fixture test per
rule; embedded-KB repro tags enforced by unit test; external `-kb` still
supported (repro not required for field-written KBs).

**Fault harness (test/faults.sh):** 17 namespace scenarios pass in this
environment (link_down, apipa, no-default-route, dead gateway + unresolved
ARP, WAN-down-LAN-fine, low path-MTU, metric conflict, VPN debris, full
tunnel, broken dual-stack, hosts override, empty resolv.conf, resolver
disagreement + hijack via two fake local resolvers, fake captive portal,
dead proxy). Runs rootless (`unshare -rn`/`-rnm`). Netem tier (gateway_lossy,
upstream_lossy via filtered netem, high_jitter, dns_slow,
high_retransmit_ratio) is **scripted but functionally gated**: the harness
verifies netem actually shapes before trusting it, and skips honestly on
kernels/sandboxes where tc is cosmetic (as in the environment this was
built in — run on a real kernel to exercise the tier).

**Output & NFR skeleton:** layer report with L1–L7 now attributable;
`-md` Markdown rendering; `-json`; `-save`; `netdiag ref` (ports, subnets,
error codes, layer legend — §6.3); per-collector timeouts with
timeout-as-a-finding (multi-probe collectors declare larger slices, total
passive sweep ≈ 28 s < 30 s budget); `--anon` redaction with a recorded
per-fact policy, unclassified-fact-drops-by-default, tested as a security
control (§4.3); read-only assertion in every report; exit 1 on criticals.

## Partials closed in the v1.1 hardening pass

- **Wi-Fi:** now reads SSID, BSSID, frequency→channel/band, and PHY rate
  via wireless-extensions ioctls (the cfg80211 compat layer every mainline
  driver still answers) — no nl80211 client needed for the common cases.
  SSID is Drop and BSSID is OUI-masked under `--anon`.
- **DHCP lease:** dhclient `expire` parsing → `dhcp_lease_hours_left`.
- **DoH/DoT:** Chrome/Chromium/Edge managed-policy read, plus
  **on-the-wire detection** — established connections to known DoH (443)
  and DoT (853) resolver endpoints from the kernel's own table; new
  `doh_bypass_active` and `browser_doh_enabled` rules, both with
  namespace repros.
- **DNSSEC:** hand-built query with the DO bit, AD-flag read on a
  known-signed zone → `dnssec_validating` + `dnssec_not_validating` rule.
- **Proxy/PAC:** WPAD PAC fetch + FindProxyForURL validation
  (`pac_unusable` rule), and a TLS-inspection root-CA scan of the trust
  store (Zscaler/Fortinet/Netskope/… → `tls_inspection_ca` rule).
- **Event history:** syslog/messages fallback when journalctl is absent,
  and time-clustering — `link_flap_peak_window` ("14:00–15:00") from
  journal timestamps, the spec's demo sentence made a fact.
- **Firewall reality:** new elevated-tier collector — nftables/iptables
  ruleset read, input-policy detection, and heuristic reconciliation of
  listening ports against accept rules (`firewall_blocking_listeners`
  rule, namespace repro with real nft rules). Skips honestly when
  unprivileged: firewall state is never silently green.
- **NAC/802.1X:** supplicant presence + managed interfaces
  (`dot1x_supplicant_present`); full auth-state needs the supplicant
  control protocol (still partial, below).
- **NIC driver:** name/version + USB selective-suspend state.
- **Interactive pruning:** `why … -ask` asks "Wired or Wi-Fi?" and drops
  the irrelevant branch (v5 §7's binary-question rule).

## Closed via the wpa_supplicant control socket (0.4.1)

One read-only unixgram protocol (STATUS / SIGNAL_POLL / SCAN_RESULTS —
never SCAN: the cache is read, nothing is transmitted) closed both
remaining wireless partials:

- **802.1X/EAP auth state:** key_mgmt, Supplicant PAE state, EAP state,
  port status — wired EAP interfaces included; feeds the new
  `dot1x_auth_failed` rule (critical, L2) and a "802.1X authentication"
  step in `why wifi`.
- **Channel occupancy / roaming context:** neighbour count, co-channel and
  adjacent-channel AP counts, same-SSID BSS count (roaming candidates),
  plus supplicant-grade RSSI/noise/linkspeed. New `wifi_channel_congested`
  rule and a "channel occupancy" step in `why wifi`.

Needs read access to /var/run/wpa_supplicant (root or the netdev group);
`wpa_ctrl_available: false` is reported honestly otherwise. Parsers are
unit-tested against captured protocol output.

## Still partial (honestly)

- **Roaming thrash over time:** BSSID-flap counting needs event history or
  `watch` (v1.3); the scan cache gives candidates, not the flapping itself.
- **NetworkManager-internal supplicants:** NM sometimes runs wpa_supplicant
  without a control dir; then occupancy needs nl80211 (still deferred).
- **Firewall reconciliation:** string-level rule matching — complex
  rulesets (sets, maps, jump chains) exceed it; labelled heuristic.
- **DoH detection:** IP-list based; a DoH server on an unknown IP evades it.

## Windows collectors — field-accepted (0.5.4, 2026-07-19)

Acceptance run on a real AD lab: Windows Server 2025 DC (French locale,
corp.local, libvirt VM). `scan`, `baseline`, `-save`, `why no-internet`
and `why cant-login corp.local` all fully green; honest skips (nic_power
on virtio, wifi without WLAN service) reported as not-green. Six field
bugs were found by the runs and fixed (0.5.1→0.5.4): NetworkProfile
events counted as link flaps; resets-per-1k on idle counters; hardcoded
"four segments"; IPv6-first DC ping false negative; localized nltest
output (judge by exit code); secure-channel false positive on the DC
itself (NTDS registry detection → not-applicable). Remaining Windows
items need a Win 11 *member* VM: member secure channel, netsh wlan,
cant-print spooler state.

**AD fault scenarios run on the live domain (0.5.5):** #1 public-resolver
DNS → `ad_dns_public_resolver` fired critical/certain and the walk's
downstream steps dashed honestly rather than blaming the DC; #2
resolver-order (public primary + DC secondary) → SRV survived via
fallback and the fault surfaced correctly as `dns_slow` with the
"dead primary, working secondary" next step; #6 deleted `_gc` SRV →
"kerberos=true gc=false — partial SRV zone", everything else still ✓,
netlogon restart reverted it. Scenarios #3 (clock skew), #4 (secure
channel) and #5 (DC down) are not measurable from the DC itself and
wait on the member VM. Field bug #7 came out of these runs: the §8
verdict claimed "not visible from this machine" while the walk held a
certain break — the blame partition only measures the transport path,
so `BlameTable.NoteUnattributed` now re-headlines config/service faults
above it (walk break, or any critical finding on a plain scan) without
overwriting a real segment failure. Unit-tested, field-confirmed.

## Windows collectors — implementation notes

All 20 collectors now have real Windows implementations (0.4.0):
IP Helper via stdlib LazyDLL (routes, ARP, TCP/UDP tables, TCP statistics,
DNS servers, DHCP lease incl. expiry, interface speed/error counters,
IcmpSendEcho for all pings — unprivileged on Windows), stdlib net.* for
interfaces/addressing, and the OS's own tools where Windows keeps the
truth behind a CLI: `netsh wlan` (SSID/BSSID/channel/signal), `netsh
advfirewall` (state + inbound policy), `wevtutil` (link-flap/Wi-Fi/DHCP
event mining), `dsregcmd /status` + `nltest /sc_query` (domain/Azure join
+ secure channel — feeds the cant-login walk's L7 check), `reg` (WinINET
proxy, Chrome DoH policy, NIC PnPCapabilities), `certutil` (TLS-inspection
CA scan). Virtual adapters (Hyper-V/WSL/loopback) are filtered so a
healthy laptop doesn't look multi-homed.

**Compile-verified only** — see WINDOWS_TESTING.md for the Win 11 VM
acceptance checklist. Known absences (honest): duplex, path-MTU, IPv6
default-route fact, per-rule firewall reconciliation.

## Remaining for a spec-complete v1

- ~~Windows VM acceptance run~~ **done on the DC (0.5.4)**; Win 11
  member-VM items still open (member secure channel, wlan, spooler).
- ~~AD fault-scenario runs~~ **scenarios 1, 2, 6 passed on the DC**; 3, 4, 5
  need the member client — see **WIN11_ONE_PASS.md**, the single checklist
  that covers every remaining field item in one VM session.
- ~~cant-print's local spooler/queue state~~ **shipped (0.6.0)**, awaiting
  the same one-pass run.
- More rules as real tickets arrive (the feedback verb now captures the
  evidence for that).
- **Signed single-binary packaging** — needs real signing keys/infra;
  deliberately not faked here.
- NL/FR/DE output templates (EN kept per decision).

## What is left after v1.3

The spec's passive/self-scoped core is now complete: v0 → v1 → v1.1 → v1.2
→ v1.3 all shipped and field-tested. Everything still open is either
authorization-gated (and therefore a deliberate later decision), needs
hardware/keys, or is polish:

- **Field acceptance of 0.6.0** on the Win 11 member client
  (WIN11_ONE_PASS.md) — the last testing debt.
- **Signed packaging** — needs real signing keys; deliberately not faked.
- **GPO last-processing result** (gpresult parsing) — the one §6.4 gap.
- **nl80211** for NetworkManager-internal supplicants; richer firewall
  reconciliation; DoH detection beyond the IP list.
- **Authorization-gated tiers** (§10 throughput/bufferbloat, §11 VLAN,
  §12 hygiene, §13 frontier) — out of scope for the passive releases and
  a conscious choice to make, not a backlog item to drift into.
