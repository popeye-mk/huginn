# Network Diagnostician — Design Spec (v2.3)

A cross-platform (Windows + Linux, macOS later) **portable single-binary** network troubleshooting tool that discovers the network a machine is standing on, classifies what it finds, and returns a **diagnosis in plain language with a named OSI layer and a verdict on whose fault it is** — instead of making a technician run nmap and Wireshark and interpret the output themselves. Zero agent, zero enrolment, one signed binary, offline-capable.

> **What changed in v2:** the tool moves from a *snapshot* to a *verdict over time*. Added: a time-domain `watch` mode for intermittent faults (the hardest ticket class); a headline **blame-partition verdict** (me / LAN / ISP / destination); throughput-vs-contracted and **bufferbloat** collectors; VLAN/segmentation reality; a first-class **network-hygiene / security-posture** section; and a clearly-fenced **§13 Frontier** tier for honestly-speculative capability plus a **§14 what-would-break-the-moat** list. The discipline is unchanged: everything is marked passive-safe or authorization-gated, and padding is called out as padding rather than shipped as ambition.
>
> **What changed in v2.1:** added **§17 Platform & Portability** — this is a portable single binary (not Electron, not an install) that runs from a USB stick on a machine with no runtime, with the language decision (**Go**) recorded and justified against the spec's own constraints. See the changelog.
>
> **What changed in v2.2:** closed four gaps that matter for day-to-day helpdesk volume rather than lab-grade fault-finding: **NTP/time-sync** joins the passive collector set (§4.1) because clock drift masquerades as broken auth/TLS/VPN; two new triage profiles, `why cant-print` and `why cant-rdp` (§6.1), give the same layer-walk treatment to the two ticket classes that come in almost as often as "no internet"; a `--for-user` plain-language report mode (§6.2) turns a technical finding into a pasteable ticket-closure sentence; and an offline **`netdiag ref`** cheat-sheet mode (§6.3) rides for free on a tool that is already a USB stick with nothing else available. None of these need new privilege tiers or authorization gates — they are v1/v1.1-tier, passive-safe, and cheap to add early.

> **What changed in v2.3:** the one-tool consolidation release. The stated goal is sharpened: this tool exists so a technician stops needing **3–5 separate tools** (ping + traceroute + nslookup + nmap + a speedtest + Event Viewer) to answer one ticket. Eight additions, all serving that consolidation: **`why cant-login`** joins the triage set (§6.4) — the AD/domain layer-walk (SRV records, Kerberos/LDAP/SMB ports, secure channel, clock) that rivals "no internet" in ticket volume; **retrospective event mining** (§4.1) reads the link-flap/Wi-Fi-disconnect/DHCP history the OS *already logged* — `watch`, backwards, for free; the DNS collector gains **hosts-file override, browser-DoH bypass, and resolver-disagreement** checks; **passive TCP pathology counters** (retransmits/resets from the OS's own stack statistics); **NIC power-saving and leftover-VPN-debris** detection (orphaned TAP adapters / NDIS filter drivers — two classic laptop tickets); **`netdiag compare good.json bad.json`** (§7.1) — diff the broken machine against the working one sitting next to it; a **`netdiag feedback`** verb (§5.3) so the self-growing KB has an actual data source and a measured false-positive rate; and a **netem/namespace fault-injection test harness** (§16.1) so every KB rule ships with an automated reproduction, not just a fixture. A **v0 walking skeleton** is added to the roadmap (§18) and the spec is declared **frozen for building** — the next artefact is a binary, not a v2.4.

> **Relationship to Diagnostic Companion (v5):** this is not a separate product. It is the network half of Diagnostic Companion grown up — same envelope, same versioned schema, same interpreter engine, same confidence/severity/next-step model, same offline/zero-agent story, same self-growing KB. The machine collector answers *"what is wrong with this box?"*; the network diagnostician answers *"what is wrong with this network, from where this box is standing?"* Everything in v5 §3 (privilege tiers, read-only guarantee, timeouts, "absence is never health", confidence) and §13 (threat model) applies here unchanged unless this document overrides it.

---

## 1. Positioning — What Exists Today (honest version)

The credibility rule from the parent spec applies with full force here: the first person who knows this space will say *"isn't this nmap?"* or *"isn't this PingPlotter?"* or *"NetAlly already does this in hardware."* All three are true and all three are answered up front. Claiming to have invented network scanning is the fastest way to lose an interviewer.

| Tool | What it genuinely does well | Where it stops |
|---|---|---|
| **nmap** | The definitive host/port/service discovery engine. Mature, scriptable (NSE), the real prior art for "what is on this network". | **Data, not diagnosis.** Tells you port 445 is open; never tells you *that host is your file server, it's reachable, but it's answering 400 ms slower than its peers.* No severity, no plain language, no next step, no layer attribution, no ticket concept. Needs an operator who already knows what the output means. |
| **Wireshark / tcpdump** | Ground-truth packet capture, unmatched depth. | Expert-only, per-question, no aggregation, no interpretation, no report, no workflow. You must already suspect the answer to find it. |
| **PingPlotter / SmokePing / MTR** | Path latency and loss over time, visualised well. | Still expert-read; no discovery, no classification, no L1/L2 findings, no "which host", no diagnosis in words. |
| **NetAlly EtherScope / AirCheck, Fluke LinkRunner** | Genuinely *interpret* — duplex mismatch, PoE faults, cable length. The real prior art for "network fault in plain language". | **A €2,000–5,000 hardware box.** Not software, not on the sick machine, not on the laptop you just plugged in at a client site. One device per technician, not one binary per USB stick. |
| **Auvik / Domotz / ThousandEyes** | Continuous network monitoring, topology maps, alerting — and they interpret. | **Agent + collector + subscription + enrolment.** Nothing runs on a network that was never onboarded, or a one-off visit to a stranger's site. Cloud-dependent. |
| **Meraki / Ubiquiti / vendor dashboards** | Excellent interpretation and topology for their own gear. | One vendor, requires their hardware and their cloud, blind to everything else on the wire. |
| **Angry IP Scanner / Advanced IP Scanner / Fing** | Fast, friendly host discovery; Fing even classifies device types. | Discovery only — a list of hosts, not a diagnosis. No layer attribution, no "why is it slow", no fault interpretation, no baseline/drift, no workflow. |
| **`ip` / `ping` / `traceroute` / `ss` / `arp` / `nslookup`** | Universal, instant, every tech knows them. | Raw, single-question, no correlation, no interpretation, Windows/Linux syntax split. |

### The honest moat

Network discovery and scanning are **not** novel — nmap did it properly decades ago, Fing classifies devices, and NetAlly interprets faults in a €3,000 box. The defensible combination is narrower and stronger, and it is the same shape as the parent spec's moat:

1. **An interpretation layer, not a scan layer.** nmap answers "what is on the wire?"; this answers *"what is wrong with this network and what do I do?"* — in the user's language, with a severity, a **named OSI layer**, and a next step.
2. **Software, not a €3,000 box.** The NetAlly-grade "this is a duplex mismatch" interpretation, delivered by a free signed binary that runs on the machine already in front of the technician.
3. **Zero agent, zero enrolment, offline-capable.** One binary on a USB stick diagnoses a network that was never onboarded, at a client site visited once, including from a machine you just plugged in.
4. **Layer attribution — it tells you where to *stop* looking.** Every finding tagged L1–L7. *"Your cable is fine, DNS is fine, the application on 443 is refusing — stop looking at the network."* Telling a technician where the problem is **not** is as valuable as telling them where it is.
5. **A network baseline that drifts.** Same philosophy as the machine baseline: *"a new host appeared answering ARP for the gateway's IP"* — rogue-DHCP and ARP-spoof detection that no affordable software tool does.
6. **It grows from your resolved tickets.** The same self-learning, quarantine-governed KB (v5 §12) — the tool gets better at *your* client networks specifically.

Anything beyond those six is a nice-to-have, not a claim.

---

## 2. Goal

Run one command — `netdiag scan` or `netdiag why slow` — and get a plain-language diagnosis of the network the machine is on: what the network *is*, what is wrong with it, at which layer, with what confidence, and what to do next. On Windows or Linux, online or offline, from a client site or a live boot, without installing an agent or onboarding anything.

**The consolidation test (v2.3):** today, answering one ordinary ticket takes a chain of 3–5 tools — `ping` + `traceroute` + `nslookup` for the path, `nmap` or Advanced IP Scanner for the neighbours, a speedtest for the bandwidth, Event Viewer / `journalctl` for the history, and the technician's head to correlate all of it. This tool exists to collapse that chain into **one command with one correlated verdict**. Every feature in this spec must pass that test: does it remove a tool from the chain or remove a correlation step from the technician's head? If it does neither, it is padding and does not ship.

---

## 3. The Authorization Gate (this is why network differs from machine)

Machine-local collection reads *your own* disk. Active network discovery touches devices you may not own. This is a different act, legally and ethically, and the tool must treat it as one. This section overrides nothing in v5 — it *adds* a constraint that only the network tool needs.

- **Passive by default.** With no flag, `netdiag` does only **passive and self-scoped** work: read local interfaces, routes, ARP/neighbour cache, DHCP lease, DNS config, the machine's own sockets, and *listen* for broadcast/multicast traffic. It sends nothing to third-party hosts except the gateway and DNS it is already configured to use. This alone diagnoses a large fraction of tickets and is always safe.
- **Active discovery is gated.** Subnet sweeps, port scans, and neighbour enumeration require an explicit `--authorized` flag (or a first-run interactive confirmation), and the tool prints exactly what it will send and to what range before doing it.
- **Scope is bounded and logged.** Active scans are confined to the local subnet by default; a wider range must be named explicitly. Every active scan records scope, timestamp, and operator into the audit log (v5 §5) — "who scanned what, where, when" is answerable.
- **The tool states the boundary in plain language.** On first active run: *"This will send discovery probes to up to 254 hosts on 192.168.1.0/24. Only do this on a network you are authorised to test."* A diagnostic tool that quietly port-scans a client's network is a tool that gets its author fired.
- **Read-only on the wire, too.** The parent spec's read-only guarantee extends here: the diagnostician never reconfigures an interface, never changes a route, never sends a DHCP release, never de-auths anything. `netdiag fix` (opt-in, dry-run default, separate module) is the only component permitted to change local network state, and it never touches remote devices.

Everything else in v5 §3 — privilege tiers, timeouts, "absence is never health", confidence levels, performance budget, graceful degradation — applies here as written.

### 3.1 Privilege model (network-specific additions)

| Tier | Runs as | Network capability |
|---|---|---|
| **Unprivileged** | normal user | interfaces, routes, ARP cache read, DNS config, own sockets, DHCP lease read, ping, traceroute (usually), TCP connect scan, HTTP probes, Wi-Fi scan (partial) |
| **Elevated** | root / Administrator | raw sockets (SYN scan, accurate ping sweep), promiscuous listen, full Wi-Fi RSSI/PHY detail, ARP-spoof detection, interface PHY/duplex/link registers, 802.1X state |
| **Offline/live-boot** | root, from Ventoy | link state, negotiated speed/duplex, DHCP behaviour, captive portal, everything not needing the target's normal OS to be up |

- Unprivileged connect-scan is slower and less stealthy than a raw-socket SYN scan but needs no elevation — the tool uses it automatically and marks the finding `method: tcp_connect`.
- `netdiag scan --explain-privileges` prints which findings are degraded without root (e.g. "duplex/PHY state needs administrator").

---

## 4. Part A — Network Collectors

Runs locally on the machine, from a Ventoy live boot, or (later) remotely via the Ops Console. Every collector uses the v5 per-collector envelope: `status` (`ok` | `skipped` | `timeout` | `error`), `reason`, `duration_ms`, `privilege_level`, and declares a timeout and kill policy. Absence is never health.

### 4.1 Passive / self-scoped collectors (always run, no authorization needed)

- **Interfaces & link:** every NIC, up/down, MAC, negotiated **speed and duplex**, MTU, carrier state, error/drop counters. Duplex/speed mismatch lives here — the classic "gigabit port running 100 half" that NetAlly charges €3,000 to detect.
- **Addressing:** IPv4/IPv6 addresses, scope, DHCP vs static, **DHCP lease** (server, lease age, expiry, renewal state), APIPA/link-local-only detection (169.254/fe80-only = "no DHCP answered").
- **Routing:** full route table, default gateway(s), **metric conflicts** between interfaces (Wi-Fi + Ethernet both default, wrong one winning), leftover VPN routes, blackhole routes, source-routing anomalies.
- **Neighbours (ARP/NDP):** ARP/neighbour cache read, **duplicate-IP / IP-conflict detection**, gateway MAC stability (a changed gateway MAC is an ARP-spoof signal), incomplete-entry ratio.
- **DNS config & correctness:** configured resolvers, **which resolver actually answered**, resolution test against known-good names, **split-horizon / hijack detection** (internal name resolving to a public IP, or a known-good public name resolving to a LAN address = captive portal or DNS hijack), DNSSEC validation state, DoH/DoT in use, resolver latency. **v2.3 adds the three classic hidden causes:** (a) **hosts-file overrides** — a stale `/etc/hosts` / `drivers\etc\hosts` entry silently pinning a name to a dead IP; (b) **browser-DoH bypass** — Firefox/Chrome resolving over DoH to a third party while the OS resolver is fine, which is why "we fixed DNS but the browser is still broken"; (c) **resolver disagreement** — the two configured resolvers returning *different* answers for the same internal name (split-DNS misconfiguration), tested by querying each resolver directly and diffing.
- **Own sockets / listening ports:** `ss -tulpn` / `Get-NetTCPConnection` — what is listening, on which interface, bound where. Answers "is the service actually up and bound?" — half of "the app can't connect" is a bind or firewall-local problem, not a network problem.
- **Local firewall reality:** not just enabled/disabled but **is it dropping the port the app needs** — reconcile listening sockets against firewall rules and report the mismatch.
- **Gateway & upstream reachability:** ping/latency to gateway, to first hop beyond, to a known-good public target; separate "LAN is fine, WAN is down" from "the whole stack is dead".
- **Path quality (`net_quality`):** loss %, latency min/avg/max/mdev, jitter over an N-packet window to gateway and to a public anchor — the difference between "internet is down" and "internet is bad". **MTU / path-MTU black-hole detection** (VPN connects but large packets vanish → Teams screen-share dies while chat works). This is the collector `why slow` currently has to guess at.
- **IPv6 health:** IPv6 present but broken (AAAA resolves, IPv6 path dead → long connect-timeout-then-fallback delays that *feel* exactly like slow internet and are invisible to most techs).
- **Captive portal / link-layer reality:** known-good HTTP 204 probe vs. redirect, portal detection, DHCP-offered DNS vs. expected, NAC/802.1X authentication state.
- **Proxy / PAC:** system proxy vs. PAC file reachability and validity, proxy-configured-but-unreachable, TLS-inspection root CA present in trust store (enterprise middlebox breaking odd sites).
- **VPN state:** tunnel adapters up/down, split vs. full tunnel, DNS-inside-tunnel sanity, VPN route correctness.
- **Wi-Fi (passive):** current SSID, BSSID, RSSI, band, channel, PHY rate, channel utilisation/co-channel interference where the driver exposes it, roaming thrash (rapid BSSID flapping), driver in use.
- **Time sync (NTP):** configured time source (domain-issued via NTP/w32time, `chrony`/`systemd-timesyncd`, or none), last-sync age, and measured **clock offset** against the system's own source and, where reachable, a known-good anchor. Clock drift beyond a few minutes breaks Kerberos ticket issuance (AD auth failures that look like "the network is down"), invalidates TLS certificate checks (a client with the wrong clock rejects a perfectly good cert), and can desync VPN handshakes — all reported by the app or the OS as a connectivity fault, never as "check the clock". This is a one-line passive read (`w32tm /query /status`-equivalent or `chronyc tracking`) that closes a ticket class disproportionate to its collection cost.
- **TCP pathology counters (passive stack statistics):** read the OS's own protocol counters — `/proc/net/snmp` + `netstat -s` on Linux, `Get-NetTCPConnection`/`netstat -s` on Windows — for **retransmission ratio, connection resets, and failed connection attempts since boot**. An 8% retransmit rate on the machine's own traffic is a free, zero-probe, zero-privilege health signal that feeds `why slow` with measured evidence instead of guesswork. No capture, no capture privilege — the kernel already counted it.
- **NIC power management & driver reality:** Wi-Fi/Ethernet adapter **power-saving mode** (the #1 cause of "the Wi-Fi drops when the laptop sits idle"), USB selective-suspend on USB/dock NICs, and driver name/version/date. On Windows, additionally detect **leftover VPN debris**: orphaned TAP/TUN adapters and stray NDIS lightweight filter drivers from uninstalled VPN clients — a classic silent connectivity killer that survives the uninstall. Both are one-line reads and both are natural future `netdiag fix` candidates (local-only, per §3).
- **Event history — the retrospective collector:** mine what the OS **already logged**: link up/down transitions, Wi-Fi disconnects *with reason codes*, DHCP failures/renewals, and network-profile changes, from Event Log (Windows) and `journalctl`/NetworkManager (Linux), over a bounded window (default 24–72 h). *"This link flapped 14 times in the last 24 hours, clustered between 14:00–15:00"* is an **intermittent-fault finding available instantly, passively, without waiting** — it is `netdiag watch` (§9) pointed backwards in time, and it costs nothing but a log read. When `watch` later runs, it correlates forward samples against this history.
- **Domain/AD client state (Windows, passive):** domain-joined vs. Azure AD-joined vs. workgroup (`dsregcmd /status`), configured DNS suffix/search list, machine **secure-channel health** (`Test-ComputerSecureChannel`-equivalent, read-only), and last Group Policy processing result. Collected passively here; consumed by the `why cant-login` triage walk (§6.4).

### 4.2 Active / authorized collectors (require `--authorized`)

- **Subnet discovery & host inventory:** ARP/ND sweep (L2, fast, LAN-only) plus optional ICMP/TCP sweep; live-host list with MAC → **OUI vendor** classification.
- **Device classification:** infer role from open ports + OUI + hostname + mDNS/SSDP/LLMNR/NetBIOS responses — *"this is a printer, this is a NAS, this is the DNS server, this is a Ubiquiti AP, this is a Windows domain controller"*. Fing-grade classification, but feeding the interpreter, not just a list.
- **Rogue-DHCP detection:** send a DHCP DISCOVER and see **how many servers answer**. More than one offer on a network that should have one DHCP server is a top-tier "half the office randomly loses internet" ticket, invisible to every software tool in §1.
- **Service reality per host:** targeted port probe of discovered hosts (connect-scan by default, SYN with root), banner/version where offered, TLS cert expiry/subject on TLS ports.
- **Peer-relative quality:** the differentiator — probe latency/loss to *each* discovered host and compare. *"Loss to 192.168.1.20 is 12%; loss to every other host on the subnet is 0% — the problem is that host or its switch port, not your machine and not the network."*
- **mDNS/LLMNR/SSDP/NetBIOS census:** what each host advertises; also flags LLMNR/NetBIOS enabled (a security finding — these are spoofing/poisoning vectors).
- **Switch/topology hints:** LLDP/CDP frames if any arrive (switch name, port ID, VLAN) — turns "which port is this?" from a cable-trace into a printed answer.
- **Wireless environment (active/monitor where supported):** neighbouring BSSIDs, channel occupancy, co-channel and adjacent-channel interference, rogue-AP / evil-twin candidates (same SSID, different BSSID/vendor).

### 4.3 Output

One structured JSON/YAML blob, same shape regardless of OS, carrying `schema_version` from day one — identical envelope to the parent spec so everything downstream (interpreter, ticket attachment, diff, correlation) is platform- and tool-agnostic. A network snapshot and a machine snapshot share the same outer schema and can live on the same ticket.

**Redaction layer (v5 §4.3) extended for network:** `--anon` masks public IPs, MACs (OUI kept, host bits masked), SSIDs, hostnames, internal topology, serial numbers, TLS cert subjects. A network snapshot is an infrastructure map of someone's site — it is at least as sensitive as a machine snapshot, and redaction is tested as a security control, not a feature. Same rule: any new schema field with no redaction decision recorded fails the test.

---

## 5. Part B — Interpreter with Layer Attribution

Same engine as v5 §6 — string/threshold/if-this-then-that rules, no ML for v1 — with one network-specific addition: **every finding carries a `layer` (L1–L7)**, and the report is organised so a technician can see, at a glance, which layers are clean and which are not.

```yaml
# net_kb/entries.yaml (examples)
- id: duplex_mismatch
  match:
    link_duplex: half
    link_speed_below_negotiable: true
  layer: L1
  finding: "Link running at 100 Mbps half-duplex on a gigabit-capable port — almost certainly a bad cable or a forced/mismatched port setting. This alone explains severe slowness and intermittent loss."
  severity: critical
  confidence: likely
  next_step: "Reseat/replace the cable; check the switch port's speed/duplex config; retest."

- id: rogue_dhcp
  match:
    dhcp_offer_count_above: 1
  layer: L2
  finding: "More than one DHCP server answered on this subnet. A rogue/second DHCP server hands out conflicting addresses — the classic cause of 'random machines lose internet'."
  severity: critical
  confidence: certain
  next_step: "Identify the extra DHCP server by MAC/OUI (listed below); disable it or isolate its switch port."

- id: gateway_mac_changed
  match:
    gateway_mac_changed_since_baseline: true
  layer: L2
  finding: "The gateway's MAC address changed since baseline. On a stable network this should not happen — possible ARP spoofing or a gateway hardware swap."
  severity: warning
  confidence: possible
  next_step: "Confirm whether the gateway was legitimately replaced; if not, investigate for ARP spoofing."

- id: dns_hijack_suspected
  match:
    known_good_public_name_resolves_to_private_ip: true
  layer: L7
  finding: "A well-known public domain is resolving to a private/LAN address — captive portal, DNS hijack, or a misconfigured internal resolver."
  severity: warning
  confidence: likely

- id: ipv6_black_hole
  match:
    aaaa_resolves: true
    ipv6_path_dead: true
  layer: L3
  finding: "IPv6 addresses resolve but the IPv6 path is dead. Applications try IPv6 first, wait, then fall back to IPv4 — this feels exactly like 'slow internet' and is easy to miss."
  severity: warning
  confidence: likely
  next_step: "Fix or cleanly disable IPv6 on this segment; do not leave it half-working."

- id: mtu_black_hole
  match:
    small_packets_ok: true
    large_packets_dropped: true
  layer: L3
  finding: "Small packets pass but large ones are silently dropped — a path-MTU black hole (common over VPN/tunnels). Web browsing works; large transfers and Teams screen-share stall."
  severity: warning
  confidence: likely
  next_step: "Lower MTU/MSS on the tunnel interface (try 1400) and retest large transfers."

- id: peer_relative_loss
  match:
    loss_to_host_above: 5
    loss_to_subnet_peers_below: 1
  layer: L3
  finding: "Packet loss to one host is high while the rest of the subnet is clean — the fault is that host or its switch port, not your machine or the network."
  severity: warning
  confidence: likely

- id: clock_drift
  match:
    ntp_offset_seconds_above: 120
  layer: L7
  finding: "System clock is off by more than the domain/TLS tolerance. This causes Kerberos authentication failures and TLS certificate rejections that present as 'can't connect' or 'can't log in' — not as a clock problem."
  severity: warning
  confidence: likely
  next_step: "Correct the time source (domain NTP / chrony) and force a resync; retest the original complaint before looking further at the network."

# --- v2.3 rules ---

- id: link_flap_history
  match:
    link_updown_events_24h_above: 10
  layer: L1
  finding: "The link went down and up repeatedly in the last 24 hours (from the OS's own event log — no waiting required). Repeated flapping points at a failing cable, a dying NIC/switch port, or a power-management setting — and it explains 'it drops sometimes' without running a watch."
  severity: warning
  confidence: likely
  next_step: "Reseat/replace the cable, try another switch port, and check NIC power-saving; if it persists, run `netdiag watch` to timestamp the next occurrence live."

- id: hosts_file_override
  match:
    hosts_file_entry_shadows_dns: true
  layer: L7
  finding: "A hosts-file entry is overriding DNS for this name — the machine never asks the resolver at all. A stale hosts entry pinning a name to an old or dead IP is a classic invisible cause of 'only this site is broken, only on this PC'."
  severity: warning
  confidence: certain
  next_step: "Review the hosts file entry (listed below); remove or correct it and retest."

- id: resolver_disagreement
  match:
    configured_resolvers_disagree: true
  layer: L7
  finding: "The two configured DNS resolvers return different answers for the same internal name — a split-DNS misconfiguration. Depending on which resolver answers first, the same machine intermittently works and fails."
  severity: warning
  confidence: likely
  next_step: "Point the machine at the internal resolver(s) only, or fix the forwarder on the resolver giving the wrong answer."

- id: tcp_retransmit_high
  match:
    tcp_retransmit_ratio_above: 3
  layer: L4
  finding: "The machine's own TCP statistics show a high retransmission ratio — packets are being lost or delayed somewhere on the path, and every connection is silently paying for it. This is measured from the kernel's counters, not a capture."
  severity: warning
  confidence: likely
  next_step: "Cross-check with net_quality loss/jitter and the blame-partition verdict to localise which segment is dropping."

- id: nic_power_save
  match:
    wifi_power_saving: true
    complaint_contains: intermittent
  layer: L1
  finding: "The wireless adapter has aggressive power saving enabled — the most common cause of 'Wi-Fi drops when the laptop sits idle for a while'. The link is healthy when tested, which is exactly why this one evades every live test."
  severity: info
  confidence: possible
  next_step: "Disable power management on the adapter (device power settings / iw power_save off) and observe for a day."

- id: vpn_driver_debris
  match:
    orphaned_tap_adapter_or_filter_driver: true
  layer: L2
  finding: "A leftover virtual adapter or filter driver from an uninstalled VPN client is still bound to the network stack. VPN debris routinely breaks or slows connectivity long after the VPN itself is gone."
  severity: warning
  confidence: likely
  next_step: "Remove the orphaned adapter/filter driver (listed below), reboot, and retest."

- id: secure_channel_broken
  match:
    domain_joined: true
    secure_channel_healthy: false
  layer: L7
  finding: "This machine's secure channel to the domain is broken — the computer account's trust with AD has failed. Users see 'the trust relationship between this workstation and the primary domain failed' or simply cannot log in; the network underneath is often perfectly fine."
  severity: critical
  confidence: certain
  next_step: "Re-establish the machine trust (Reset-ComputerMachinePassword / rejoin); do not troubleshoot the network further for this complaint."
```

Everything from v5 §6 carries over unchanged: rule precedence and de-duplication, confidence-driven wording, unmatched data shown raw rather than hidden, NL/FR/EN/DE translated findings, locale-independent matching (match on numeric state and event IDs, never on localised interface strings).

### 5.1 The layer report

The signature output. Instead of a flat list, findings roll up into a **clean/not-clean verdict per layer**:

```
  L1  Physical      ✗  100 Mbps half-duplex on gig port  →  see finding
  L2  Data link     ✗  rogue DHCP (2 servers answering)   →  see finding
  L3  Network        ✓  addressing, routing, IPv4 path OK
  L4  Transport      ✓  no port/socket anomalies
  L7  Application     ✗  DNS resolving public name to LAN IP →  see finding

  Verdict: the network is being hurt at L1 and L2. Fix the cable/duplex and the
  rogue DHCP first — the L7 DNS oddity may be a downstream symptom of them.
```

Telling a technician *"L3 and L4 are clean, stop looking there"* is half the value. No affordable software tool does this today.

### 5.2 Network baseline & diff

Same motion-detector philosophy as v5 §6.1, applied to the network:

- `netdiag baseline` — save the current network state as known-good for *this location* (gateway MAC, DHCP server, host inventory, DNS servers, subnet, typical loss/latency).
- `netdiag scan --diff` — surface **what changed**: a new host, a disappeared server, a changed gateway MAC, a second DHCP server, a new open port on a known host, DNS servers changed, loss/latency regressed against the location's normal.
- This is what turns rogue-DHCP and ARP-spoof detection from "is two servers wrong?" (sometimes it's legitimate) into *"a second DHCP server appeared that was not here yesterday"* — a far stronger, lower-false-positive signal.

### 5.3 The feedback verb — `netdiag feedback` (v2.3)

The self-growing KB (v5 §12) has so far assumed a data source without naming one. This is it:

```
netdiag feedback <finding-id> confirmed     # the finding was the real cause
netdiag feedback <finding-id> wrong         # the finding fired but was not the cause
netdiag feedback <finding-id> wrong --note "legit second DHCP: failover pair"
```

- **One command at ticket-closure time**, against a finding ID already printed in every report. Costs the technician five seconds; produces the only data that can make the KB honest.
- Feedback is stored **locally** next to the KB (a plain append-only file — no cloud, per §14), and rolls up into a **per-rule confirmed/wrong ratio**. A rule whose false-positive rate climbs gets its confidence demoted or its thresholds tuned — with evidence, not opinion.
- `wrong --note` entries are exactly what feeds the quarantine (v5 §12): *"two DHCP offers can be a legitimate failover pair"* becomes a candidate suppression/refinement rule that a human promotes.
- This is deliberately a verb, not telemetry: nothing is sent anywhere, nothing runs in the background, and a tool that is never given feedback simply keeps its seed confidence levels. The KB grows only where someone feeds it.

---

## 6. Symptom-Driven Triage (network)

Same complaint-first entry point as v5 §7, network-flavoured:

```
netdiag why slow           # loss/jitter/MTU/duplex/IPv6/wifi/peer-relative
netdiag why no-internet    # DNS/gateway/DHCP/captive-portal/link
netdiag why cant-reach X   # targeted: route → DNS → port → TLS to one host/service, layer by layer
netdiag why cant-print     # targeted: reach → spooler/queue state → port (9100/IPP/LPD/SMB) → driver mismatch
netdiag why cant-rdp       # targeted: reach → port 3389 → NLA/cert → licensing/session-limit, layer by layer
netdiag why cant-login     # targeted: DC reach → AD SRV records → Kerberos/LDAP/SMB ports → clock → secure channel
netdiag why wifi           # RSSI/channel/interference/roaming/band
netdiag why intermittent   # the hardest ticket: baseline-diff + loss-over-window + rogue-DHCP + ARP stability
```

`netdiag why cant-reach fileserver` is the strongest demo: it walks L3→L7 to one target and names the exact break — *"route to it exists (L3 ✓), DNS resolves it (L7 ✓), but TCP 445 is refused (L4 ✗) — the file-sharing service on that host is down or firewalled. Stop looking at your network."* Interactive pruning (v5 §7, max two binary questions) applies: "Wired or Wi-Fi?" removes the whole wireless branch in one keystroke.

Unknown symptom → falls back to a full `netdiag scan` (passive tier), same graceful-degradation principle.

### 6.1 `why cant-print` and `why cant-rdp` — the other two "no internet"

"Can't print" and "can't RDP in" are, by ticket volume, right behind "no internet" and "it's slow" on most SMB helpdesks — and both are really a `cant-reach` layer-walk wearing a different name, which is why they belong here rather than as a separate feature:

- **`netdiag why cant-print <printer-or-queue>`:** reachability to the print server or the printer's own IP (L3), then the specific transport — raw/JetDirect on **9100**, **IPP** (631), **LPD** (515), or an **SMB print-share** (445) depending on how it is configured — probed layer by layer exactly like `cant-reach`. Where the target is a Windows print queue, the local spooler/queue state (paused, stuck job, driver mismatch) is read as an L7 finding before blaming the network at all. *"Port 9100 to the printer is open and answering (L4 ✓) — the queue itself is paused on this machine (L7 ✗). Not a network problem."* This reuses the exact `cant-reach` engine with a printer-aware target profile; it is not new plumbing.
- **`netdiag why cant-rdp <host>`:** reachability (L3), TCP **3389** open/refused/filtered (L4), then the RDP-specific L7 causes that generate the most confusing tickets: **NLA (Network Level Authentication) mismatch**, an expired/self-signed RDP certificate the client is silently rejecting, the host's **concurrent-session/licensing limit** reached, or RDP disabled at the host. *"Port 3389 is reachable (L4 ✓) but the connection is refused at the TLS/NLA stage (L7 ✗) — check NLA settings or the host's session limit, not the route to it."*

Both profiles share the layer-walk engine and the blame-partition framing (§8) already built for `cant-reach` — they are target-aware presets, not new architecture, which keeps them cheap to add and honest about what they are.

### 6.2 Plain-language mode — `--for-user`

Every triage command above defaults to the technical report (layer report, confidence, next step, in the technician's own language). `--for-user` renders the **same finding** a second way: one or two jargon-free sentences fit to paste directly into a ticket-closure note or a client email, with the layer/confidence machinery stripped out rather than translated. *"The printer itself is online and reachable — the print job was stuck in a paused queue on this PC. I've resumed it and printing is confirmed working again."* This is a rendering option on the existing interpreter output (same rule fires, same finding object, different template) — it costs a second output template per KB entry, not a second diagnosis, and it is aimed squarely at closing tickets faster rather than at demonstrating technical depth.

### 6.3 Offline reference — `netdiag ref`

Since the binary is already a self-contained USB stick with no internet guaranteed, a bundled, static lookup table costs almost nothing to ship and earns its place standing in a server room with no signal: common port numbers and what runs on them, private/CGNAT/APIPA subnet ranges, RFC1918 vs. public quick-check, common Windows/Linux network error codes and their usual meaning, and the tool's own OSI-layer legend. `netdiag ref port 445`, `netdiag ref subnet 169.254.0.0/16`, or a plain `netdiag ref` for the full sheet. Deliberately static text, no probing, no privilege needed, no authorization gate — it is a cheat sheet, not a collector, and it is honestly labelled as one rather than dressed up as a finding.

### 6.4 `why cant-login` — the third "no internet" (v2.3)

On any domain-joined SMB network, **authentication tickets rival "no internet" in volume** — and they are the most mis-triaged, because an AD failure *presents* as a network failure and gets an hour of cable-wiggling before anyone checks the domain. It is the same `cant-reach` layer-walk engine wearing a domain-aware target profile, which is why it belongs here and not as a separate feature:

- **`netdiag why cant-login [domain]`** walks, in order: **DC discovery** — do the AD SRV records (`_ldap._tcp.dc._msdcs.<domain>`) resolve, and against *which* resolver (a client pointed at a public DNS server cannot find its DC — the single most common cause) → **DC reachability** (L3) → **the AD port set** — Kerberos **88**, LDAP **389**, SMB **445** (SYSVOL/GPO), Global Catalog **3268** — open/refused/filtered (L4) → **clock offset** against the DC (already collected, §4.1 — Kerberos tolerates ±5 min) → **machine secure-channel health** (L7, from the passive domain-state collector) → last **Group Policy** processing result.
- Each step reuses existing collectors; the profile only supplies the target logic and the AD-specific L7 checks. Sample verdict: *"Your DC resolves and is reachable, all AD ports answer (L3/L4 ✓), the clock is in tolerance — but this machine's secure channel to the domain is broken (L7 ✗). Reset the machine trust; stop looking at the network."* Or the other classic: *"This machine's DNS points at 8.8.8.8, which cannot resolve AD SRV records — it will never find the domain controller. Point DNS at the DC and retest before anything else."*
- Blame-partition framing (§8) applies with an AD-flavoured fourth column: me / LAN / **DC-or-domain** / destination.
- This is also the profile that most directly demonstrates the eindwerk competence set (AD forest, DNS, Kerberos/NPS, GPO) in a runnable artefact — every check in the walk maps to a competence an interviewer can ask about.

---

## 7. Fleet / Multi-Point Correlation

The parent spec's fleet correlation (v5 §8) gains a network-native meaning: run the diagnostician from **several points** on the same network and correlate.

- *"Loss to the gateway is 0% from the wired segment but 9% from every Wi-Fi client — the problem is the AP or the wireless medium, not the WAN."*
- *"All three probe points see the same second DHCP server — confirmed rogue, not a fluke."*
- Correlation needs a denominator (v5 §8): "3 of 3 points see it" is a very different finding from "1 of 3".

No monitoring stack — just reading snapshots taken from a few machines you already have access to.

### 7.1 `netdiag compare` — the working machine is the best baseline (v2.3)

Multi-point correlation (§7) asks *"do several points agree?"*. The everyday helpdesk move is simpler and older: **the machine on the next desk works — what's different?** v2.3 makes that a first-class command instead of leaving it to eyeballing two reports:

```
netdiag scan --save good.json        # on the colleague's working machine
netdiag scan --save bad.json         # on the broken one
netdiag compare good.json bad.json   # → interpreted diff
```

- The output is not a raw JSON diff but an **interpreted delta**: only the differences that a KB rule or a heuristic considers diagnostic, ranked. *"The broken machine differs in three ways: a system proxy is set (the working one has none), MTU is 1400 vs 1500, and DNS points at a resolver the working machine doesn't use. The proxy is the most likely cause of the complaint — start there."*
- **Nearly free by construction:** both snapshots already share the versioned schema (§4.3), and the diff engine is the baseline-diff engine (§5.2) pointed at a second machine instead of a second point in time. Same code, third use.
- Works offline and cross-machine by design — carry `good.json` on the same USB stick as the binary, walk to the broken machine, and get the verdict without either machine needing the other reachable.
- Honest limits, stated in the output: comparing different OSes or different hardware produces expected differences; the interpreter suppresses known-benign deltas (hostnames, MACs, lease timestamps) and says what it ignored.

---

## 8. The Blame-Partition Verdict — "is it me, my LAN, my ISP, or the destination?"

Every "it's slow" / "it's broken" ticket lives in one of four segments, and the technician's first job is always to work out which. The tool has the pieces already (local link health, gateway reachability, peer-relative loss, upstream/WAN reachability, destination-specific probes); v2 makes the *conclusion* an explicit headline instead of leaving the technician to assemble it.

```
  Blame partition
  ──────────────────────────────────────────────
  This machine     ✓  link, IP, DNS, sockets all healthy
  Your LAN         ✗  9% loss to gateway over Wi-Fi; wired peers clean
  Your ISP / WAN   ✓  once past the gateway, path to internet is clean
  The destination  ✓  target host reachable and fast when LAN is bypassed

  Verdict: the problem is your LAN — specifically the Wi-Fi path to the
  gateway. Not your machine, not your ISP, not the site you're trying to reach.
```

- One top-line sentence, backed by the four-segment table, above every other finding in a `why slow` / `why cant-reach` run.
- Each segment is `✓`, `✗`, or `unknown` (the v5 "absence is never health" rule — a segment whose probe was skipped is `unknown`, never silently green).
- This is the single most-repeated sentence in network support work, and no consumer tool states it. It is also the most useful thing to hand a user to relay to their ISP: *"the tool says the problem is past your gateway, in the ISP path"* ends an hour of the ISP blaming the router.
- Confidence-gated (v5 §3.5): a segment is only blamed `certain` on a directly measured fact, `likely` on a strong inference.

---

## 9. Time-Domain Mode — `netdiag watch` (the intermittent-fault release)

Everything up to here is a photograph. The hardest ticket in network support — *"it's slow sometimes"*, *"it drops a few times a day"*, *"calls stutter but only in the afternoon"* — cannot be caught by a photograph, and it is exactly the ticket every snapshot tool (including nmap, Fing, a single MTR run) fails on. `netdiag watch` is the motion-camera to the snapshot's still.

- **Passive long-run:** sits on the connection for a chosen window (minutes to hours), sampling loss, latency, jitter, Wi-Fi RSSI/BSSID, DHCP events, ARP stability, and route changes on an interval — and **timestamps the anomaly** when it fires. *"At 15:04 loss to the gateway spiked to 22% for 40 seconds, coinciding with an RSSI drop and a BSSID roam — this is a Wi-Fi roaming/coverage event, not an ISP problem."*
- **Catches the periodic:** a DHCP renewal storm every N minutes, 3 pm channel congestion as the office fills, a scheduled backup saturating the uplink, a flapping link that re-negotiates duplex. Periodicity itself is a finding — "this recurs every ~30 minutes" points straight at a cause a single sample never could.
- **Event log, not a dashboard:** the output is a timestamped list of interpreted events plus a summary verdict, not a live graph to babysit. This deliberately stays on the zero-agent side of the line — it is a bounded diagnostic run you start and read, not a monitoring daemon (see §14). `--duration 2h --interval 5s`.
- **Baseline-aware:** watch compares against the location baseline (§5.2), so "loss spiked to 22%" is reported against "normal here is 0%", not in a vacuum.
- Passive-safe: needs no `--authorized` because it only observes the machine's own traffic and pings its own gateway/anchor. This is the strongest capability that is *also* safe to run anywhere.

---

## 10. Throughput & Bufferbloat — "we pay for 200, it feels like 20"

Two of the highest-volume "slow internet" tickets are answered today by fast.com and a shrug. Both deserve an interpreted answer.

- **Throughput vs. contracted (`throughput`):** a consented, bounded throughput probe — to the gateway (LAN ceiling), to a self-hosted iperf3 target if configured (the honest measurement), or to a careful public target — reported as *delivered vs. expected* and *LAN vs. WAN bottleneck*. *"LAN throughput to the gateway is 940 Mbps; WAN throughput is 43 Mbps against a 200 Mbps contract — the bottleneck is past your gateway. Raise it with the ISP; your LAN is fine."* Gated behind an explicit flag because it consumes bandwidth and, to a public target, egresses — it is off in the default run and states its data cost before running.
- **Bufferbloat / latency-under-load (`bufferbloat`):** the finding that impresses. Idle latency is 6 ms; under a saturating upload it climbs to 340 ms — *this* is why the video call stutters while speedtest reports "fine", and it is invisible to every consumer tool. Measured by sampling latency during a controlled transfer and reporting the delta and grade (A–F, the DSLReports-style scale techs recognise). *"Bufferbloat: latency rises 6 ms → 340 ms under load (grade F). Calls and gaming will stutter whenever anyone uploads. Fix: enable SQM/fq_codel on the router."* A concrete, correct, actionable finding no free tool gives in words.

---

## 11. VLAN & Segmentation Reality

Directly relevant to SMB/KMO network work, and straight out of the eindwerk VLAN/firewall competence.

- **Which VLAN am I actually on:** inferred from the DHCP scope received, the subnet, and LLDP/CDP VLAN hints (authorized). *"You pulled an address from the guest scope (192.168.50.0/24) on a port that should be corporate VLAN 10 — likely a mis-tagged switch port."*
- **Segmentation check (authorized):** can the guest segment reach the corporate segment when it should not? A bounded, consented reachability probe across segments turns "are we actually isolated?" from an assumption into a tested answer — the question an auditor and a security-conscious SMB both ask.
- **Native-VLAN / trunk leakage hints:** unexpected VLAN tags arriving on an access port (from LLDP/CDP or tagged frames) flagged as a misconfiguration.

---

## 12. Network Hygiene & Security Posture (first-class output)

The tool already collects most of this; v2 surfaces it as a dedicated section rather than a side effect. This is the SOC-adjacent competence the background already points at, presented as something a security-conscious SMB actually wants.

- **Poisoning exposure:** LLMNR / NetBIOS-NS / mDNS responders enabled — the classic Responder-attack surface. Flagged with the one-line "why this matters" and the fix.
- **Plaintext & legacy protocols on the wire:** SMBv1 alive, Telnet/FTP/HTTP management interfaces answering, unauthenticated services — each a finding with severity and next step.
- **Exposed management surfaces:** SSH/RDP/web-admin/SNMP open on infrastructure or on hosts that should not offer them; default-credential-likely devices (by banner/OUI) flagged as *worth checking*, never asserted.
- **TLS hygiene on internal services:** expired, self-signed, weak, or soon-to-expire certificates on internal HTTPS endpoints — the "expired cert generates the most bizarre-looking ticket in existence" problem, caught before the ticket.
- **Rogue / unexpected infrastructure:** the rogue-DHCP and ARP-drift findings (§4.2, §5.2) reframed here as security posture, not just correctness.
- **Shadow-IT / unexpected devices:** baseline-diff (§5.2) plus classification flags *"a consumer device (Amazon OUI) appeared on the corporate subnet"* — the shadow-IT ticket.

Every item is confidence-gated and, where it touches other hosts, authorization-gated. This section is explicitly *reporting*, never *exploitation*: it names exposure and the fix, and does nothing offensive — the same read-only discipline as everywhere else.

---

## 13. Frontier Tier (honestly speculative — labelled as such on purpose)

These are real capabilities, but each carries a caveat that keeps it out of the core claim. Listing them separately is itself the credibility move: it shows the author can tell a shipped feature from an aspiration. None of these belongs in an interview pitch as "the tool does this" — only as "here's where it could go."

- **Short interpreted packet capture (`capture`, authorized):** a bounded pcap that interprets *top talkers, TCP resets, retransmission rate, DNS failures, TLS alerts* — "Wireshark's conclusion without reading Wireshark". Caveat: capture is privileged, sensitive, and easy to over-scope; it stays gated, bounded, `--anon`-by-default, and interpretive-only (it never becomes a packet browser — that's Wireshark's job, §14).
- **PoE / cable-length / TDR readout:** where a managed switch (via SNMP/LLDP) or a capable USB-Ethernet adapter exposes it — cable length, fault distance, PoE class/draw. Caveat: hardware-dependent, only partial coverage, so it can never be a promised feature, only a bonus when the gear cooperates. Closes more of the NetAlly gap where possible.
- **Local-LLM summariser for the unmatched tier (an Anora skill):** feed the "unrecognised" findings and raw captures to a local model, get a *draft* KB rule or a plain-language summary back. Caveat (identical to v5 §22): the LLM never writes to the KB directly and never touches `fix` blocks — its output enters quarantine like any ticket-learned rule and a human promotes it. It drafts; it never decides.
- **Passive OS/device fingerprinting (p0f-style):** infer device OS from passive traffic characteristics without active probing — extends classification into the passive tier. Caveat: probabilistic, ages badly as stacks change, so always `possible` confidence, never a headline.
- **Path-change / route-flap detection over long watch runs:** BGP-adjacent symptoms visible even from an endpoint (the default route's next-hop changing, traceroute path instability). Caveat: an endpoint sees a keyhole view of routing; report what's visible, never over-claim to diagnose the ISP's core.
- **Import adapters as inputs, not rivals:** ingest nmap XML, a Fing export, an MTR/PingPlotter log, or an iperf3 result and *interpret* it. Caveat: this is integration polish, not core capability — worth doing precisely because it turns the closest competitors into front-ends for your interpreter.
- **Assisted-remediation suggestions for remote gear:** generate the *exact* config snippet to fix a finding (the fq_codel line, the switchport duplex command, the DHCP-snooping config) — as text to hand a network admin. Caveat: it **prints**, it never applies to a device it doesn't own (§14). Suggestion, not action.

---

## 14. What Would Break the Moat (deliberately *not* built)

The discipline that makes the tool credible is knowing what to refuse. Each of these is a plausible-sounding "ultimate" feature that would quietly destroy the thing that makes this tool worth building.

- **Continuous monitoring dashboards / a daemon.** That is Auvik/Domotz/Zabbix, and it breaks the zero-agent, zero-enrolment moat the instant it needs to run all the time. `watch` stays a bounded run you start and read (§9), never a service.
- **Active remediation of remote devices.** Reconfiguring a switch or a remote host violates the read-only-on-the-wire guarantee (§3) that lets a technician trust the tool on a client's network. `fix` stays local-only, dry-run-default, whitelisted (v5 §13).
- **A full packet browser.** Rebuilding Wireshark's decode-everything UI is a decade of work and misses the point — the value is the *conclusion*, not the packet tree. `capture` interprets and stops (§13).
- **Autonomous scanning without the gate.** Any "just scan everything continuously" convenience feature detonates the authorization discipline (§3) that keeps the author employed rather than fired.
- **Cloud aggregation of snapshots.** The moment topology maps of clients' networks live in someone's cloud, the tool becomes the liability it was designed not to be. Snapshots stay on the ticket, local, redacted (v5 §5).
- **Exploitation / active security testing.** The hygiene section (§12) *reports* exposure; turning it into a scanner-that-attacks makes it a pentest tool with a pentest tool's legal and trust profile, which is a different product with a different buyer.

Refusing these on purpose is not a limitation to apologise for — it is the specification.

---

## 15. Wow-Factor Demos (each under a minute, no cloud, no ML)

- **`netdiag why cant-reach <host>`** — the layer-walk to a single target that ends in one sentence naming the exact break and the layer to stop looking at. The single best interview demo.
- **Rogue-DHCP catch** — spin up a second DHCP server in the KVM lab, run `netdiag scan --authorized`, watch it name the rogue by vendor OUI. "How did it know that?" in ten seconds.
- **Duplex-mismatch call** — force a port to 100-half in the lab; the tool says "bad cable or forced port, this is why it's slow" — the €3,000-NetAlly trick, free.
- **The layer report** — the clean/not-clean-per-layer card that tells a tech where *not* to look.
- **Baseline diff** — take a baseline, plug in a new device, `--diff` names the new host and its vendor instantly.
- **`--anon` export** — one flag turns the full infrastructure map into something safe to paste into a vendor ticket or a forum, redaction proven by test.
- **The blame-partition verdict** — run `why slow` over a throttled Wi-Fi link in the lab; the tool prints "the problem is your LAN, not your ISP or the destination" as a headline. The one sentence every ticket needs.
- **Bufferbloat grade F** — saturate the lab uplink, watch idle latency jump 6 ms → 300 ms and the tool call it out with the SQM fix. "How did it know the calls stutter?" — because it measured latency-under-load, which nothing else does in words.
- **`netdiag watch` catches the intermittent** — script a periodic loss spike in the lab, let watch run, watch it timestamp the event and name the periodicity. The hardest ticket class, solved.
- **`why cant-login` names the AD break** *(v2.3)* — point a domain-joined KVM guest's DNS at 8.8.8.8; the tool prints *"this machine cannot resolve AD SRV records — it will never find the DC"* in one run. The eindwerk AD forest becomes the live test bench, and the demo maps one-to-one onto interview questions.
- **`netdiag compare` finds the difference** *(v2.3)* — snapshot a healthy guest, break a proxy/MTU setting on its clone, run `compare`, and watch it rank the diagnostic differences in one screen. The "why does hers work and mine doesn't" ticket, answered mechanically.
- **The retro catch** *(v2.3)* — flap a guest's link overnight with a cron loop; next morning a plain `netdiag scan` says *"this link flapped 22 times, clustered at 03:00"* from the journal alone — the intermittent caught **without** running watch at all.

---

## 16. Constraints carried from v5 (unchanged, stated for completeness)

Read-only guarantee (extended to the wire, §3), per-collector timeouts with timeout-as-a-finding, "absence is never health", confidence levels gating exit codes and headline placement, performance budget (passive sweep < 30 s, active LAN discovery < 60 s on a /24 or reports what it dropped), offline-by-construction default (no egress beyond the machine's own gateway/DNS unless `--ticket`/`--authorized`/`--remote`), graceful degradation everywhere, versioned schema, redaction-as-security-control, signed single binary, the AV/code-signing showstopper (v5 §13.1), and the full threat model (v5 §13) — a tool that port-scans and reads infrastructure topology is exactly what an attacker wants to own, so untrusted collected data is treated as hostile input, no shell interpolation of hostnames or banners, strict schema validation, HTML output escaped.

### 16.1 Fault-injection test harness — every rule ships with its reproduction (v2.3)

Fixtures prove the interpreter matches; they do not prove the *collectors measure the fault*. The KVM lab covers that manually (§15's demos), but manual demos don't run in CI. The upgrade: **Linux network namespaces + `tc netem` + tiny service containers** can fabricate almost every fault in the KB deterministically, on the dev box, in seconds:

- `tc netem loss 12%` on a veth pair → `peer_relative_loss` and `net_quality` findings, reproducibly.
- `tc netem delay 300ms` under a saturating stream → the bufferbloat grade.
- An interface with lowered MTU and ICMP-frag-needed dropped → the `mtu_black_hole` rule, end to end.
- Two `dnsmasq` instances in one namespace → `rogue_dhcp` without touching a real network.
- `ip link set ... down/up` in a loop → `link_flap_history` from real journal entries.
- A resolver pair configured to disagree → `resolver_disagreement`.

**The rule of the rule:** from v1 onward, *a KB entry is not merged unless it carries either a netem/namespace reproduction script or an explicit `repro: hardware-only` tag* (duplex forcing, PoE, RSSI need real gear and stay in the KVM/physical lab list). This turns "tested" into "provably tested", keeps rule quality honest as the KB grows from tickets, and — since it is namespaces and `tc`, not a lab — runs on every commit. Windows-specific collectors are covered by fixtures plus the KVM Windows guest; the harness does not pretend otherwise ("absence is never health" applies to test coverage too).

---

## 17. Platform & Portability — one binary, every OS, no runtime

This is a **portable single binary, not an Electron app and not an install**. The design premise — *run it on a stranger's broken PC off a USB stick, possibly headless, possibly from a live boot* — dictates the whole architecture, and it rules out anything that needs a runtime, a desktop session, or an installer.

### 17.1 Not Electron, and why

- Electron bundles a full Chromium browser (~150 MB+), which contradicts the < 40 MB binary budget and the < 150 MB RAM ceiling — and this tool runs on machines *already* under memory pressure.
- The core case is often **headless**: over SSH/WinRM, from a Ventoy live boot, on a server with no GUI. Electron needs a desktop session and cannot run there. The tool must.
- A 150 MB packed Electron binary that reads SMART/topology and scans networks is an even worse AV silhouette (v5 §13.1) than a small one.
- Electron is the right tool for a sit-in-front-of-it desktop app (e.g. the ESG VSME Builder). It is the wrong tool for a diagnostic that must run *anywhere*, including where there is no screen.

### 17.2 The shape: one CLI binary per OS, from one codebase

- **A single self-contained executable per OS** — Windows `.exe`, Linux ELF, macOS Mach-O later — built from one shared codebase. No Python, no Node, no .NET, nothing to install on the target. Drop one file on a USB stick and it runs.
- **The UI is a terminal plus an optional self-contained HTML report.** The CLI runs headless and, on request, writes a single portable `.html` (all CSS/JS inlined, no external assets) that opens in any browser for the visual layer — the layer report, blame-partition, and timeline rendered without shipping a browser. Same pattern as the parent spec.
- **Portable means stateless-by-default:** no registry keys, no install directory, no service. Config and KB are files the binary reads next to itself or from an explicit path, so the whole tool — binary + KB + config — can live on the USB stick and leave nothing behind on the target (the read-only-to-the-target guarantee, §3).

### 17.3 Language: Go (the decision, recorded)

Go is chosen for the shippable tool, for reasons that are all spec constraints rather than taste:

- **Truly static binary.** Go compiles to one standalone executable with no runtime and no dependency to be missing on the target — the single most important stability property for a tool that runs where nothing is installed. Contrast PyInstaller, which unpacks to a temp directory at every launch and fails exactly where this tool is used most: full disk, locked-down temp, aggressive AV.
- **Clean AV silhouette.** No interpreter bundle, no temp-unpack step — a far better starting position against Defender/SmartScreen than a 40 MB+ Python bundle that extracts and executes from temp (v5 §13.1). Signing is still mandatory; Go just starts cleaner.
- **Size, speed, footprint** all land inside the spec budgets — sub-40 MB, fast startup, low RAM — which matters when the tool is run dozens of times a day on sick machines.
- **One-command cross-compilation.** `GOOS=windows GOARCH=amd64 go build` produces the Windows binary from a Linux dev box; every target builds from one machine. For a solo developer shipping cross-platform, a standing time saving, not a one-off.
- **Network/system calls are Go's home turf** — interfaces, routes, ARP, sockets, DHCP, ICMP — which is most of what the collectors do. The interpreter (YAML rules, threshold/string matching) is trivial in either language, so Python's library depth buys little here.
- **Prior art:** the modern tools this most resembles — Tailscale and most current network CLIs — are Go, for exactly these reasons.

**Honest caveat and the pragmatic path:** if Go is new, there is a real learning curve. A reasonable middle route is to prototype the *interpreter and rules engine* in Python to prove the concept fast, then build the shippable tool in Go once the shape is clear — but since the static binary is load-bearing and this is a long-term build, starting in Go and treating it as a deliberately-added, directly-employable skill is the better long-run call. **Python + Nuitka/zipapp remains the documented fallback** if Go proves impractical, at the cost of the AV silhouette and the temp-unpack fragility above.

### 17.4 Per-OS reality (abstracted behind the schema)

The collector layer is the only OS-specific code; everything above it (schema, interpreter, layer report, blame-partition, KB) is platform-agnostic because the envelope makes every collector's output the same shape (§4.3).

- **Linux:** `netlink` / `/proc` / `/sys` and `ip`/`ss`-equivalent syscalls, `nl80211` for Wi-Fi, raw sockets (root) for SYN/ARP work.
- **Windows:** IP Helper API (`iphlpapi`), WMI / `Get-NetTCPConnection`-equivalents, the native Wi-Fi API (`wlanapi`), `dsregcmd` state where relevant.
- **macOS (later):** the schema already does not care; the OSX-KVM VM is a free test bench (v5 §22).
- Where a capability is unavailable on an OS, the collector emits `status: skipped, reason: not_applicable` — the "absence is never health" rule (v5 §3.4) makes cross-OS gaps visible rather than silently green.

**One binary, three operating systems, no runtime, no install, no browser bundled — portable in the strict sense: it runs from a USB stick on a machine that has nothing.**

---

## 18. Roadmap

**v0 — the walking skeleton (v2.3: build this before touching the spec again)**
The spec is now larger than anything built, which is the moment to stop specifying and start compiling. v0 is deliberately small enough to ship in weeks: **five passive collectors** (interfaces/link+duplex, addressing/DHCP lease, routing/gateway, DNS config + one resolution test, gateway/upstream ping) → the envelope + versioned schema → the interpreter with **five seed rules** (duplex mismatch, APIPA/no-DHCP, no default route, DNS resolution failure, gateway unreachable) → the **layer report** as the output → one Go binary, Linux first, cross-compiled for Windows even if the Windows collectors are stubs that honestly report `skipped`. No signing yet, no HTML, no triage verbs. **Definition of done: `netdiag scan` on the OptiPlex and in a deliberately broken KVM guest prints a correct layer report.** Everything after v0 is iteration on a running tool; everything before it is paper.

**v1 — passive, self-scoped, useful and safe on day one**
Passive collectors (interfaces/duplex, addressing/DHCP, routing, ARP/neighbour, DNS config+correctness **incl. hosts-file override, browser-DoH bypass, resolver disagreement**, sockets, gateway/upstream reachability, `net_quality` loss/jitter/MTU, IPv6 health, captive portal, proxy/PAC, VPN, Wi-Fi passive, **NTP/clock offset**, **TCP pathology counters**, **NIC power-saving + VPN-debris detection**, **event-history mining (link flaps / Wi-Fi disconnects / DHCP failures from the OS logs)**, **domain/AD client state (passive)**) → interpreter with layer attribution + ~18 seed rules from real homelab/support issues → **layer report** → terminal + Markdown output → fixtures-based tests **plus the netem/namespace fault-injection harness (§16.1) with the repro-or-tagged rule in force** → signed single-binary packaging → v5 NFR skeleton (timeouts, privilege tiers, "not checked" section, read-only assertion, redaction test). No active scanning yet — nothing that needs `--authorized` — so v1 is safe to run anywhere without a consent conversation. `netdiag ref` (§6.3) ships here too: static, zero-cost, no privilege needed.

**v1.1 — the "why can't I reach X" + blame-partition release**
`netdiag why cant-reach <host>` layer-walk, `why slow` / `why no-internet` / `why wifi` triage profiles with interactive pruning, **`why cant-print` / `why cant-rdp`** as target-aware presets of the same layer-walk engine (§6.1), **`why cant-login`** as the AD-aware preset (§6.4 — the collectors it needs are already passive in v1), the **blame-partition verdict** (§8) as the headline of every quality run, the **`--for-user` plain-language rendering** (§6.2) on every triage command, the **`netdiag feedback` verb** (§5.3 — local append-only capture starts now so the data exists by the time the KB pipeline lands in v2), `--since` windows on quality metrics, NL/FR/EN/DE output. The blame-partition needs only passive data already collected in v1, so it comes early — it is the highest value-per-line feature in the whole spec.

**v1.2 — the network-baseline release**
`netdiag baseline` + `scan --diff`: new/disappeared host, changed gateway MAC, DNS-server change, loss/latency regression against the location's normal. Turns static findings into drift signals. **`netdiag compare good.json bad.json`** (§7.1) ships here — it is the same diff engine pointed at a second machine instead of a second point in time.

**v1.3 — the time-domain release (`watch`)**
`netdiag watch` (§9): bounded passive long-run, timestamped interpreted events, periodicity detection, baseline-aware anomaly reporting. Still passive-safe. This is the release that closes the intermittent-fault ticket class — the hardest one — and it needs the v1.2 baseline to be meaningful.

**v1.4 — the throughput & bufferbloat release**
`throughput` (delivered vs. contracted, LAN vs. WAN bottleneck) and `bufferbloat` (latency-under-load grade + SQM fix), §10. Both consent-gated for bandwidth/egress but neither needs subnet scanning — they measure the machine's own path.

**v1.5 — the authorized-discovery release (the gate goes in *before* the feature)**
Authorization gate + audit logging **first**, then: subnet discovery, OUI/device classification, **rogue-DHCP detection**, per-host service probe, **peer-relative quality**, mDNS/LLMNR/SSDP census, LLDP/CDP topology hints, VLAN/segmentation reality (§11). This is the release that needs §3 to already be solid.

**v1.6 — the hygiene & wireless release**
Network-hygiene / security-posture section as first-class output (§12): LLMNR/NetBIOS exposure, plaintext/legacy protocols, exposed management surfaces, internal-TLS hygiene, shadow-IT flagging. Plus active/monitor Wi-Fi: neighbouring BSSIDs, channel occupancy, co/adjacent-channel interference, rogue-AP / evil-twin candidates, roaming analysis.

**v2 — Ops Console integration & multi-point correlation**
Network snapshot on a ticket (shared schema with machine snapshots), `netdiag why` from the Console, multi-point correlation with denominators, Ventoy live-boot entry, snapshot hashing/verify, the self-growing KB with quarantine (v5 §12) seeded from resolved network tickets.

**Frontier (see §13 — each shipped only when its caveat is honestly met)**
- `netdiag fix` (opt-in, dry-run default, local-only): set MTU/MSS, flush DNS, renew DHCP, disable half-broken IPv6 — never touches remote devices, whitelisted commands only (v5 §13).
- Short interpreted `capture` (authorized, bounded, `--anon` default): top talkers / resets / retransmits / DNS+TLS failures — Wireshark's conclusion, not its UI.
- PoE / cable-length / TDR readout where managed-switch SNMP or a capable adapter exposes it.
- Local-LLM summariser (Anora skill) for the unmatched tier — drafts KB rules into quarantine, never writes directly.
- Passive OS/device fingerprinting (p0f-style), always `possible` confidence.
- Import adapters: nmap XML, Fing, MTR/PingPlotter, iperf3 → interpret. Competitors become front-ends.
- Assisted-remediation *text* for remote gear (the exact config line) — prints, never applies.
- macOS collector (schema already doesn't care; the OSX-KVM VM is a free test bench).

---

## 19. Why this is defensible as a portfolio piece *and* a real tool

It demonstrates, in one runnable artefact, exactly the competences a Belgian IT-support/network role screens for: DHCP, DNS, ARP, routing, duplex/PHY, Wi-Fi, VPN, TLS, the OSI model used *correctly* to localise a fault, and the security awareness to gate active scanning and treat a topology map as sensitive data. It is grounded in real homelab work (KVM lab as the rogue-DHCP and duplex-mismatch test bench, HSI/hardening sensibility, Ventoy offline story) so every line is defensible in an interview — and because it shares the parent spec's schema and interpreter, it is not a second project to maintain but the same one, answering the other half of the question.

---

## 20. Changelog

**v2.3 (this document) — the one-tool consolidation release, and the spec freeze**
- Sharpened the goal (§2) with the **consolidation test**: every feature must remove a tool from the 3–5-tool chain (ping/traceroute/nslookup/nmap/speedtest/Event Viewer) or remove a correlation step from the technician's head — otherwise it is padding and does not ship.
- Added **§6.4 `netdiag why cant-login`** — the AD/domain layer-walk (DC discovery via SRV records, Kerberos/LDAP/SMB/GC ports, clock tolerance, secure channel, GPO result). Authentication tickets rival "no internet" in volume and are the most mis-triaged as network faults; the profile reuses the existing `cant-reach` engine plus a new passive domain-state collector.
- Added four passive collectors to §4.1: **TCP pathology counters** (retransmit/reset ratios from the kernel's own statistics — zero probes, zero privilege), **NIC power-saving + leftover-VPN-debris detection** (orphaned TAP adapters / NDIS filters — two classic laptop tickets), **event-history mining** (link flaps, Wi-Fi disconnect reasons, DHCP failures read from Event Log/journalctl — `watch` pointed backwards in time, available instantly), and **domain/AD client state** (feeds §6.4).
- Extended the DNS collector with the three classic hidden causes: **hosts-file overrides**, **browser-DoH bypass**, and **resolver disagreement** (split-DNS misconfig detected by querying each resolver and diffing).
- Added **§7.1 `netdiag compare good.json bad.json`** — an interpreted, ranked diff between a working and a broken machine; the baseline-diff engine pointed at a second machine, so nearly free by construction.
- Added **§5.3 `netdiag feedback`** — the KB's actual data source: a five-second confirmed/wrong verb at ticket-closure, stored locally, producing per-rule false-positive rates and feeding the quarantine with evidence instead of opinion.
- Added **§16.1 the fault-injection test harness** — network namespaces + `tc netem` reproduce loss, latency-under-load, MTU black holes, rogue DHCP, link flaps and resolver disagreement deterministically in CI; from v1, a KB rule is not merged without a reproduction script or an explicit `repro: hardware-only` tag.
- Added seven v2.3 seed rules to §5 (`link_flap_history`, `hosts_file_override`, `resolver_disagreement`, `tcp_retransmit_high`, `nic_power_save`, `vpn_driver_debris`, `secure_channel_broken`) and four demos to §15.
- Restructured the roadmap (§18): a **v0 walking skeleton** (five collectors, five rules, layer report, one Go binary, done in weeks) now precedes v1; `cant-login` and `feedback` land in v1.1, `compare` in v1.2. **The spec is frozen at v2.3 for building — the next deliverable is a binary, not a v2.4.**
- Fixed the title, which still read v2.1.

**v2.2**
- Added **NTP/clock offset** to the passive collector set (§4.1) plus a matching KB rule (`clock_drift`, §5) — clock drift breaks Kerberos/TLS/VPN in ways that present as pure connectivity faults, and it is a one-line passive read.
- Added **§6.1** `netdiag why cant-print` and `netdiag why cant-rdp` — target-aware presets of the existing `cant-reach` layer-walk engine, covering the two ticket classes (print, remote-desktop) that run at volumes close to "no internet" on most SMB helpdesks. No new architecture: same engine, same blame-partition framing, printer/RDP-specific L7 checks (queue state, transport choice, NLA/cert/session-limit) layered on top.
- Added **§6.2** `--for-user` — a plain-language rendering of an existing finding, meant to be pasted straight into a ticket-closure note or client email. Same finding, same rule, a second output template — not a second diagnosis.
- Added **§6.3** `netdiag ref` — a static, offline, zero-privilege cheat sheet (ports, RFC1918/CGNAT/APIPA ranges, common error codes, the OSI legend) that rides for free on a tool that is already a USB stick with no internet guaranteed. Explicitly labelled as a lookup table, not a collector or a finding.
- Folded all four additions into the v1/v1.1 roadmap (§18) at their natural place — none needed a new privilege tier or authorization gate, so none pushed later than v1.1.

**v2.1**
- Added §17 Platform & Portability: the tool is a portable single binary, explicitly **not** Electron and not an install — one CLI executable per OS from one codebase, terminal UI plus an optional self-contained HTML report, stateless so it runs from a USB stick and leaves nothing on the target.
- Recorded the language decision: **Go** for the shippable tool (static binary, clean AV silhouette, size/speed budgets, one-command cross-compilation, network/syscall fit), with Python + Nuitka/zipapp as the documented fallback and a Python-prototype-then-Go pragmatic path.
- Documented the per-OS collector reality (Linux netlink/proc/sys, Windows IP Helper/WMI/wlanapi, macOS later) abstracted behind the shared schema, with cross-OS gaps surfaced by "absence is never health".

**v2**
- Reframed the tool from *snapshot* to *verdict over time*; title and goal now promise a whose-fault verdict, not just a description.
- Added §8 the blame-partition verdict (me / LAN / ISP / destination) as a headline output — the single most-repeated sentence in network support, stated explicitly and confidence-gated. Sequenced early (v1.1) as highest value-per-line.
- Added §9 `netdiag watch` time-domain mode — bounded passive long-run with timestamped interpreted events and periodicity detection, closing the intermittent-fault ticket class while staying zero-agent.
- Added §10 throughput (delivered vs. contracted, LAN vs. WAN) and bufferbloat (latency-under-load grade + SQM fix) — two high-volume "slow internet" tickets currently answered by guesswork.
- Added §11 VLAN/segmentation reality and §12 network-hygiene/security-posture as a first-class output (LLMNR/NetBIOS exposure, plaintext/legacy protocols, exposed management surfaces, internal-TLS hygiene, shadow-IT).
- Added §13 Frontier tier — capabilities listed *with their caveats* (short interpreted capture, PoE/TDR, local-LLM summariser, passive fingerprinting, import adapters, assisted-remediation text) so aspiration is never mistaken for a shipped claim.
- Added §14 "what would break the moat" — the features deliberately refused (continuous daemon, remote remediation, full packet browser, cloud aggregation, exploitation) because refusing them *is* the specification.
- Resequenced the roadmap: blame-partition and `watch` pulled early (passive-safe, highest value); active discovery still gated behind §3; hygiene and wireless grouped; frontier items each gated behind their honest caveat.

**v1**
- Established the network diagnostician as the network counterpart to Diagnostic Companion, sharing schema, envelope, interpreter, confidence model, redaction, threat model and KB governance.
- Added §3 Authorization Gate — the one genuinely new constraint the network tool needs: passive-by-default, active-discovery-gated, scope-bounded-and-logged, read-only-on-the-wire.
- Defined the passive collector set (safe, always-on) and the active collector set (gated): including rogue-DHCP detection, peer-relative quality, duplex/PHY, DNS-correctness/hijack, MTU black-hole, IPv6 black-hole, device classification, ARP-spoof/gateway-MAC drift.
- Added §5.1 the layer report (clean/not-clean per OSI layer) and layer attribution on every finding — the "tells you where to stop looking" differentiator.
- Added §5.2 network baseline/diff (rogue-DHCP and ARP-spoof become drift signals, cutting false positives).
- Positioned honestly against nmap, Wireshark, PingPlotter/MTR, NetAlly hardware, Auvik/Domotz, Fing and native CLI tools — cross-platform interpreted diagnosis as software, on the machine already present, as the moat rather than "we scan networks".
