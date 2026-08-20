# Changelog

All notable changes to Huginn are recorded here. Dates are ISO (YYYY-MM-DD).

## [Unreleased]

### Fixed
- **macOS connection parsing.** A real macOS run surfaced a bug the mocked
  tests could not: the connection parser was shaped for Linux `ss` and
  Windows JSON, and silently matched **zero** rows of BSD `netstat -anv`
  (protocol `tcp4/tcp6`, `address.port` joined by a dot, state in the sixth
  column). Added a proper `parse_macos` and a single `connection_format`
  selector, consolidated three copies of the parser-choice into one source
  of truth, and covered it with tests built from the real output.

### Verified
- **macOS**, on a real machine: smoke test **12 passed, 0 failed** (only the
  honest skips remain — no macOS `netdiag` binary, no hypervisor for
  backup-boot). Huginn is now verified on Linux, Windows **and** macOS.

## [1.0.0] — first public release

The first open version of Huginn, published complete with its two companion
tools (netdiag, Diagnostic Companion).

### What it does
- **LAN census** — every device on the segment, and anything new since last time.
- **Anomaly guard** — ARP-spoofing and rogue-DHCP signs (the basis of local eavesdropping).
- **Wi-Fi evil-twin detection** — impostor access points broadcasting your network's name.
- **Exposure check** — devices leaving risky ports open.
- **Name-poisoning watch** — LLMNR/NBT-NS responders.
- **Threat matching** — outbound connections against public known-bad lists.
- **Host health & backup verification** — the latter proven by actually booting a restore.
- **Corroboration** — a second machine cross-checking the first (defeats a poisoned cache).
- **Alerting** — desktop, phone push (ntfy), or email, each proven by a test alert.
- **A local console** and an hourly background patrol that catches up after downtime.

### The principles it ships with
- **Absence is never health** — coverage on every finding; "not checked" never reads as "all clear".
- **Detect and propose, never act** — no blocking, enforced by a test.
- **Zero dependencies** — Python and Go standard libraries only.
- **Runs on Linux, Windows, and macOS** — OS differences confined to one module, verified by a portability test that fakes each OS.

### Verified
- Full test battery green on Linux and Windows (45 suites, 800+ checks).
- Recovery-from-backup demonstrated on KVM and Hyper-V.
- Rebuild-from-nothing proven from a clean-machine verification disc.

### Known limits (by design, and stated in-product)
- Sees only while the machine is on, and only its own network segment.
- Detects attacks by symptom, not by capturing raw packets.
- A couple of platform paths (a Hyper-V console reader, a Windows file-ACL lockdown) are written from documentation and not yet confirmed against the real thing.

[1.0.0]: https://github.com/popeye-mk/huginn
