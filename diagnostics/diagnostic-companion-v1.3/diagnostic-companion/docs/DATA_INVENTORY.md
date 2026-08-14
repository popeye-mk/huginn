# Data Inventory (spec §5, §18)

"One table in the repo listing every schema field, whether it is
personal data, and its redaction rule." This is the artefact a DPO
actually asks for, and it's also the source of truth
`redact.py`/`tests/test_redact.py` are checked against — if a new
collector field shows up here without a matching entry in
`redact.py`'s `SECTION_REDACTORS`, that's a gap to close before it
ships in `--anon` output.

Rule key: **keep** (not personal data, always exported), **redact**
(masked with a stable hash in `--anon` output), **conditional** (masked
only if the value turns out to be public/identifying — see the note).

## Top-level

| Field | Personal data? | Rule | Note |
|---|---|---|---|
| `hostname` | Yes — identifies a specific machine/user | **redact** | Stable hash so repeated reports from the same host stay correlatable |
| `os`, `schema_version`, `collected_at` | No | keep | |

## `system`

| Field | Personal data? | Rule |
|---|---|---|
| `os`, `os_release`, `kernel` | No | keep |
| `uptime_seconds`, `uptime_days`, `last_boot_epoch` | No | keep |
| `load_avg_*`, `mem_total_mb`, `mem_available_mb`, `mem_used_percent` | No | keep |

## `network`

| Field | Personal data? | Rule | Note |
|---|---|---|---|
| `interface` | No | keep | Interface name (`eth0`, `wlan0`), not identifying |
| `gateway` | Infrastructure map | **conditional** | Redacted only if it's a public IP; private/LAN gateways are kept — needed to troubleshoot, don't identify a person |
| `dns_servers` | Infrastructure map | **conditional** | Same rule as `gateway`, applied per entry |
| `dns_resolution`, `dns_any_failed` | No | keep | Domain names probed are our own fixed list (example.com, cloudflare.com, wikipedia.org), not user data |
| `gateway_ping.target` | Infrastructure map | **conditional** | Same IP rule |
| `gateway_ping.reachable`, `public_ping.reachable` | No | keep | |
| `public_ping.target` | No | keep | Fixed constant (`1.1.1.1`) this tool chose as a probe target, not user infrastructure |

## `disk`

| Field | Personal data? | Rule |
|---|---|---|
| `volumes[].device`, `mountpoint`, `fstype` | No | keep |
| `volumes[].total_gb`, `free_gb`, `free_percent`, `min_free_percent` | No | keep |

## `logs`

| Field | Personal data? | Rule | Note |
|---|---|---|---|
| `error_count` | No | keep | |
| `entries[]` | **Yes, potentially** — free text can contain anything | **redact (best-effort)** | Pattern-scrubbed for IPv4, MAC addresses, email addresses, `/home/<user>` and `C:\Users\<user>` paths. **Not exhaustive** — this is the one field in the schema where "clean" can't be guaranteed, only "meaningfully reduced." Documented, not hidden. |

## `battery`

| Field | Personal data? | Rule |
|---|---|---|
| `batteries[].name`, `capacity_percent`, `status`, `cycle_count`, `health_percent` | No | keep |

## `wifi`

| Field | Personal data? | Rule | Note |
|---|---|---|---|
| `adapters[].interface`, `link_quality`, `signal_level_dbm` | No | keep | |
| `adapters[].ssid` | Yes — SSIDs are frequently a person's name or address | **redact** | Always masked, regardless of whether it "looks" identifying |

## `smart`

| Field | Personal data? | Rule | Note |
|---|---|---|---|
| `disks[].device`, `health`, `reallocated_sectors`, `pending_sectors` | No | keep | No serial numbers collected yet |
| *(future: disk serial number)* | Yes — a serial is a durable hardware identifier | **redact** (planned) | Not yet collected. The day a collector reads it, it needs a rule here and in `redact.py` before it ships — this row exists so that isn't forgotten. |

## What's not in this table yet

Every optional collector in the full spec (§4.2) that isn't built yet
— printers, AD domain, certificates, VPN/proxy, USB, AAD/Intune,
M365 client, firmware/BIOS serials, browser/profile — will need a row
here and a `SECTION_REDACTORS` entry before it ships. Several of those
(AAD device IDs, certificate subjects, USB device serials) are
meaningfully more sensitive than anything collected so far and deserve
real scrutiny, not a rubber-stamped "keep."
