# netdiag v1.5 — the network diagnostician

**Install on Linux:** `./install_desktop.sh` — no sudo, gives you a desktop
icon, a menu entry and the `netdiag` command. Start with
[QUICKSTART.md](QUICKSTART.md).

**Verify a build:** `netdiag selftest` — 20 checks, no network, exit 1 if this
binary's reasoning is not intact.

The v1.2 build of the **Network Diagnostician** (spec v2.3, §18 v1–v1.2):
the **motion detector** — `baseline` saves this location's known-good state,
`-diff` reports drift against it, and `compare good.json bad.json` points
the same engine at the working machine on the next desk. Plus everything
from v1/v1.1:
twenty passive collectors, thirty-nine seed rules (repro-tagged, each with
a plain-language template), the layer report with the **blame-partition
verdict as its headline**, the symptom-driven **`why` layer walks**,
`--for-user` rendering, the local **`feedback`** verb, Markdown output,
the offline `ref` cheat sheet, and the NFR skeleton (timeouts, honest
skips, `--anon` redaction). Still zero dependencies — Go standard library
only — one static binary per OS. Nothing needs `--authorized`: everything
is passive or probes only this machine's own path and targets you name.

```
./netdiag                        # passive scan + blame verdict + layer report
./netdiag why no-internet        # symptom walk: link→DHCP→ARP→gateway→WAN→DNS→portal
./netdiag why slow               # duplex/wifi/loss/jitter/MTU/IPv6/retransmits/DNS-lag
./netdiag why cant-reach host:445    # route → DNS → ping → port, names the exact break
./netdiag why cant-print printer     # same walk, 9100/IPP/LPD/SMB preset
./netdiag why cant-rdp host          # same walk, 3389 + NLA hint
./netdiag why cant-login corp.local  # AD walk: SRV → DC ping → 88/389/445/3268 → clock
./netdiag why wifi | why intermittent
./netdiag why slow -for-user     # jargon-free ticket-note rendering (§6.2)
./netdiag why no-internet -ask   # interactive pruning: "Wired or Wi-Fi?"
./netdiag feedback gateway_lossy confirmed          # ticket-closure feedback (§5.3)
./netdiag feedback rogue_dhcp wrong --note "failover pair"
./netdiag feedback               # per-rule confirmed/wrong rollup (local file only)
./netdiag -json                  # snapshot + findings + blame as JSON (schema 0.2.0)
./netdiag -md report.md          # Markdown report ('-' = stdout)
./netdiag -anon -save s.json     # redacted snapshot (per-fact policy, tested)
./netdiag -since 72              # widen the event-history window (hours)
./netdiag -kb my.json            # external KB next to the binary (USB-stick story)
./netdiag ref | ref port 445     # offline cheat sheet
./netdiag baseline               # save THIS location's known-good state (§5.2)
./netdiag -diff                  # what changed here since the baseline
./netdiag -save good.json        # on the working machine …
./netdiag compare good.json bad.json   # … interpreted ranked delta (§7.1)
```

The verdict (§8) is the sentence support work repeats all day, made a
headline: *"the problem is past your gateway, on the ISP/WAN side — not
your machine, not your LAN."* Segments are ✓/✗/unknown — a segment whose
probe was skipped is unknown, never silently green.

## What v1 measures (Linux, passive tier §4.1)
L1: link/duplex/speed, error & drop counters, carrier flaps, Wi-Fi
quality/signal + SSID/BSSID/channel/band/PHY-rate (WEXT ioctls),
supplicant-grade RSSI/noise + channel occupancy + 802.1X/EAP state via
the wpa_ctrl socket (root/netdev), NIC
power saving + driver name/version + USB selective-suspend, 802.1X
supplicant presence, event mining with flap time-clustering
("14:00–15:00") and syslog fallback.
L2: ARP cache, gateway MAC resolution state, incomplete-entry ratio.
L3: addressing/APIPA/DHCP-lease (+ hours left), routing + metric
conflicts, gateway & upstream reachability, loss/RTT/jitter windows,
kernel path-MTU, IPv6 broken-dual-stack, VPN state/full-tunnel/debris.
L4: sockets and listening ports, kernel TCP pathology counters, local
firewall reality — ruleset read + listening-port reconciliation
(elevated tier, honest skip unprivileged).
L7: DNS config + resolution + latency, hosts-file overrides, per-resolver
disagreement, hijack (public name → private IP), DNSSEC AD-flag state,
Firefox TRR + Chrome policy DoH, on-the-wire DoH/DoT connections,
captive-portal 204 probe, proxy reality + WPAD/PAC fetch-and-validate,
TLS-inspection root-CA heuristic, SNTP clock offset, AD/realm state.

Windows: all 20 collectors implemented (IP Helper via LazyDLL, netsh/
wevtutil/dsregcmd/nltest/reg/certutil parsing) — compile-verified,
awaiting the WINDOWS_TESTING.md acceptance run on a real Win 11.

## Build & test
```
go test ./...                       # rule fixtures + redaction-as-control tests
go build -o netdiag ./cmd/netdiag   # Linux
GOOS=windows go build -o netdiag.exe ./cmd/netdiag
sh test/faults.sh                   # fault injection: root or rootless (userns)
```

## The harness (§16.1)
`test/faults.sh` reproduces 23 rules plus 2 blame verdicts in throwaway
namespaces (veth pairs, bind-mounted /etc files, fake DNS resolvers, a
fake captive portal) and gates the netem tier on netem *actually shaping*
— sandboxes that accept `tc` syntax but route around the qdisc are
detected and skipped honestly. Every embedded KB rule carries
`repro: namespace|netem|hardware-only`, enforced by unit test.

## Status
See **V1_STATUS.md** for the honest ledger. Next per §18: v1.3 `watch` —
the time-domain release that closes the intermittent-fault ticket class,
building on the baseline this release added.
