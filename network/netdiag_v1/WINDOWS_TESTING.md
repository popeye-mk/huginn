# Testing netdiag on Windows 11 (VM checklist)

The Windows collectors are newly implemented and **compile-verified only** —
this checklist is the acceptance run for them. Copy `netdiag_windows_amd64.exe`
into the VM and work through it. Everything is read-only; nothing needs
admin unless noted.

## 1. Smoke test

```
netdiag_windows_amd64.exe -version        → netdiag 0.4.0-v1.1
netdiag_windows_amd64.exe ref port 3389   → RDP (static table, no network needed)
netdiag_windows_amd64.exe                 → full scan; expect a layer report,
                                            a blame table, and exit code 0 on
                                            a healthy NAT'd VM
```

Check in the scan output:
- `link` — the VM's adapter up, speed populated (from GetIfTable)
- `addressing` — the NAT address, `dhcp_lease_found: true`, DHCP server IP
- `routing` — the NAT gateway, `default_route_present: true`
- `neigh` — gateway ARP `resolved` with a MAC
- `gateway_ping` / `net_quality` — RTTs to the gateway + 1.1.1.1 (IcmpSendEcho)
- `sockets` / `tcp_stats` — nonzero counts
- `time_sync` — w32time source + measured offset (expect < a few seconds)
- `dns` / `dns_extra` — resolvers from GetNetworkParams, resolution ok
- `firewall` — `windows-advfirewall`, active true on a default Win 11
- `ad_state` — honest "not joined" on a workgroup VM

`-json` shows every collector's status; anything `error` (rather than
`ok`/`skipped`) is a bug in my struct offsets — send me that JSON and I'll fix.
The likeliest suspects on layout: `addressing` (GetAdaptersInfo lease),
`link` speed (MIB_IFROW offsets), `sockets` (MIB_TCPROW).

## 2. Fault scenarios (each maps to a rule)

- **apipa_no_dhcp** — VM settings: switch NIC to an internal/host-only
  network with no DHCP → rerun → APIPA critical + LAN blame.
- **gateway_unreachable** — set a static IP with a wrong gateway
  (e.g. 192.168.99.1) → gateway does not answer + ARP incomplete.
- **hosts_file_override** — add `10.9.9.9 test.local` to
  `C:\Windows\System32\drivers\etc\hosts` (admin) → info finding.
- **proxy_unreachable** — Settings → Proxy → manual proxy 192.0.2.1:3128 →
  critical finding; remove afterwards.
- **captive_portal** — hard to fake in a VM; verify on real hotel/guest
  Wi-Fi via the laptop instead.
- **wifi** — VM sees no Wi-Fi (honest skip expected); test the wifi
  collector on the Windows laptop itself if you have one, or check the
  Linux WEXT path on this laptop: `./netdiag_linux_amd64` should now show
  SSID/channel/band.
- **why cant-rdp** — enable RDP on the VM, then from a second machine (or
  the VM itself): `netdiag why cant-rdp <vm-ip>` → port 3389 open. Disable
  RDP → refused → "the service is down or firewalled ON THE TARGET".
- **firewall** — `netdiag -json | findstr firewall` → active + policy.
- **event_history** — disconnect/reconnect the VM NIC a few times, wait a
  minute → `link_flaps_24h` > 0 (from wevtutil).
- **`why cant-login`** — only meaningful against a domain; if you build an
  AD lab VM later, this is the §6.4 walk (SRV → DC ports → clock → secure
  channel via nltest).

## 3. What "pass" looks like

No collector in `error` status, the fault scenarios above fire their rules,
and the blame verdict matches the fault you injected. Skips are fine when
honest (no Wi-Fi in a VM, not domain-joined, event log empty).

## Known Windows limitations (by design, listed in V1_STATUS.md)

Duplex not exposed by IP Helper; path-MTU read absent (GetIpPathTable is
v-next); IPv6 default-route fact absent (GetIpForwardTable2 v-next);
firewall per-rule reconciliation not done; NIC power heuristic is the
PnPCapabilities registry bit, marked approximate.
