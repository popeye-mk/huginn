"""SMART collector (spec §4.2): disk wear and failure indicators.

Requires elevation and `smartctl` — auto-skips cleanly if either is
missing, per §3.1's "runs what it can, marks the rest skipped".

**ATA and NVMe report completely different health attributes.** This
matters more than it sounds:

    ATA/SATA:  Reallocated_Sector_Ct, Current_Pending_Sector
    NVMe:      Critical Warning, Available Spare, Percentage Used,
               Media and Data Integrity Errors

An earlier version parsed only the ATA attributes. On an NVMe drive
every one of those regexes missed, so `reallocated_sectors` and
`pending_sectors` came back null, `any_reallocated` was always False,
and both SMART rules were structurally unfireable — on the drive type
in most machines built in the last several years. The collector
reported status "ok" and the report showed no disk finding, which is
indistinguishable from a healthy disk. Found on a real Acer laptop with
an NVMe drive reporting health PASSED and nothing else.

The NVMe equivalents are not the same measurement, so they are reported
under their own names as well as folded into the cross-platform
`any_reallocated` / wear fields the KB reads. `attribute_source`
records which family was parsed, so a report never implies a precision
the device did not provide.
"""

import glob
import re
import shutil
import subprocess

from collectors.base import Skip, require_privilege

DISK_GLOBS = ["/dev/sd*", "/dev/nvme*n*", "/dev/vd*"]

# Fallback only. Every NVMe drive publishes its own
# `Available Spare Threshold`, and they differ — a real Acer laptop
# reported 5% where 10% is often quoted as typical. The device's own
# figure is always preferred; this constant is used only when the drive
# does not report one, which is rare.
NVME_SPARE_FLOOR = 10

# A ratio needs a denominator big enough to mean something. One unsafe
# shutdown out of three boots is 33% and tells you nothing; the same
# ratio over 700 boots is a pattern. Below this, the collector reports
# no ratio at all rather than a number a rule would over-read — the
# same reasoning as refusing to report health from a zero design
# capacity (§3.4).
MIN_POWER_CYCLES_FOR_RATIO = 50


def _physical_disks():
    disks = set()
    for pattern in DISK_GLOBS:
        for path in glob.glob(pattern):
            # whole-disk devices only, not partitions (sda1, nvme0n1p2, ...)
            if re.search(r"(sd[a-z]+|vd[a-z]+|nvme\d+n\d+)$", path):
                disks.add(path)
    return sorted(disks)


def _int_or_none(match, group=1):
    """Parse a counter, tolerating locale thousands separators.

    smartctl formats large numbers using the system locale: a Dutch or
    German install prints "1.098" and "31.092.008" where an English one
    prints "1,098". Both are group separators, not decimal points —
    treating the first as a float would turn 1,098 power-on hours into
    1.098. Stripping both is correct because these counters are always
    integers.
    """
    if not match:
        return None
    raw = match.group(group).strip().replace(",", "").replace(".", "").replace(" ", "")
    try:
        return int(raw)
    except (ValueError, IndexError):
        return None


def parse_ata(output):
    """Classic ATA/SATA SMART attribute table."""
    return {
        "reallocated_sectors": _int_or_none(
            re.search(r"Reallocated_Sector_Ct.*?\s(\d+)\s*$", output, re.MULTILINE)),
        "pending_sectors": _int_or_none(
            re.search(r"Current_Pending_Sector.*?\s(\d+)\s*$", output, re.MULTILINE)),
    }


def parse_nvme(output):
    """NVMe SMART/Health Information log (NVMe Log 0x02)."""
    critical = re.search(r"Critical Warning:\s*(0x[0-9a-fA-F]+)", output)
    critical_warning = None
    if critical:
        try:
            critical_warning = int(critical.group(1), 16)
        except ValueError:
            critical_warning = None

    # Temperature thresholds are published by the drive, like the spare
    # threshold — 83/85 C on a Crucial P3, but vendors differ. Reading
    # them rather than assuming avoids the mistake corrected earlier
    # where a rule second-guessed the hardware about its own limits.
    return {
        "critical_warning": critical_warning,
        "temperature_c": _int_or_none(
            re.search(r"^Temperature:\s*(\d+) Celsius", output, re.MULTILINE)),
        "warning_temp_threshold": _int_or_none(
            re.search(r"Warning\s+Comp\. Temp\. Threshold:\s*(\d+)", output)),
        "critical_temp_threshold": _int_or_none(
            re.search(r"Critical Comp\. Temp\. Threshold:\s*(\d+)", output)),
        "power_on_hours": _int_or_none(
            re.search(r"Power On Hours:\s*([\d.,\s]+)", output)),
        "power_cycles": _int_or_none(
            re.search(r"Power Cycles:\s*([\d.,\s]+)", output)),
        "unsafe_shutdowns": _int_or_none(
            re.search(r"Unsafe Shutdowns:\s*([\d.,\s]+)", output)),
        "available_spare_percent": _int_or_none(
            re.search(r"Available Spare:\s*(\d+)%", output)),
        "available_spare_threshold": _int_or_none(
            re.search(r"Available Spare Threshold:\s*(\d+)%", output)),
        "percentage_used": _int_or_none(
            re.search(r"Percentage Used:\s*(\d+)%", output)),
        "media_errors": _int_or_none(
            re.search(r"Media and Data Integrity Errors:\s*([\d,\s]+)", output)),
        "error_log_entries": _int_or_none(
            re.search(r"Error Information Log Entries:\s*([\d,\s]+)", output)),
    }


def parse_disk(device, output):
    """One disk's SMART output into a normalised record."""
    is_nvme = "NVMe" in output or "nvme" in device

    record = {
        "device": device,
        "health": (lambda m: m.group(1) if m else "unknown")(
            re.search(r"SMART overall-health.*?:\s*(\w+)", output)),
        "attribute_source": "nvme" if is_nvme else "ata",
    }

    if is_nvme:
        nvme = parse_nvme(output)
        record.update(nvme)

        # Fold NVMe indicators into the cross-platform fields the KB
        # reads. These are different sensors from ATA's sector counts,
        # not equivalents — attribute_source records which was used.
        spare = nvme["available_spare_percent"]
        threshold = nvme["available_spare_threshold"]
        if threshold is None:
            threshold = NVME_SPARE_FLOOR

        # Judged against the drive's own published threshold, not a
        # number chosen here. A rule that second-guesses the device
        # about its own spare pool is a rule that will be wrong on some
        # hardware.
        record["spare_below_threshold"] = bool(
            spare is not None and spare < threshold)
        record["spare_threshold_used"] = threshold

        # Unsafe shutdowns as a proportion of power cycles. The absolute
        # count means nothing without the denominator: 95 is alarming on
        # a machine that has booted 200 times and unremarkable on one
        # that has booted 20,000.
        cycles = nvme["power_cycles"]
        unsafe = nvme["unsafe_shutdowns"]
        record["unsafe_shutdown_ratio"] = (
            round(unsafe / cycles, 3)
            if cycles and cycles >= MIN_POWER_CYCLES_FOR_RATIO and unsafe is not None
            else None)

        # Compared against the drive's own published limit, not ours.
        temp = nvme["temperature_c"]
        warn_at = nvme["warning_temp_threshold"]
        record["over_temperature"] = bool(
            temp is not None and warn_at is not None and temp >= warn_at)
        # Distinguish "not hot" from "could not tell". Without this a
        # reader cannot know whether over_temperature=False means the
        # drive is cool or that no threshold was available to compare
        # against (§3.4).
        if temp is not None and warn_at is None:
            record["temperature_unavailable"] = (
                "drive did not publish a warning temperature threshold")

        record["failing"] = bool(
            (nvme["critical_warning"] or 0) > 0
            or (nvme["media_errors"] or 0) > 0
            or record["spare_below_threshold"]
        )
        record["wear_percent"] = nvme["percentage_used"]
    else:
        ata = parse_ata(output)
        record.update(ata)
        record["spare_below_threshold"] = False  # not an ATA concept
        record["unsafe_shutdown_ratio"] = None
        record["over_temperature"] = False
        record["failing"] = bool(
            (ata["reallocated_sectors"] or 0) > 0
        )
        record["wear_percent"] = None

    return record


def summarise(disks):
    """Aggregate the per-disk records into the fields the KB matches on."""
    failing = [d for d in disks if d.get("failing")]
    pending = [d.get("pending_sectors") for d in disks
               if d.get("pending_sectors") is not None]
    wear = [d.get("wear_percent") for d in disks if d.get("wear_percent") is not None]

    # Only claim a health verdict where the drive actually reported one.
    unhealthy = [d for d in disks
                 if str(d.get("health", "")).upper() not in ("PASSED", "OK", "UNKNOWN", "")]

    return {
        "disks": disks,
        # Whether any drive is below *its own* published spare
        # threshold. The KB matches on this rather than on a percentage,
        # so the device's definition governs instead of a number picked
        # by whoever wrote the rule.
        "any_spare_below_threshold": any(d.get("spare_below_threshold") for d in disks),
        "any_over_temperature": any(d.get("over_temperature") for d in disks),
        "max_unsafe_shutdown_ratio": max(
            [d["unsafe_shutdown_ratio"] for d in disks
             if d.get("unsafe_shutdown_ratio") is not None] or [None]),
        "max_power_on_hours": max(
            [d["power_on_hours"] for d in disks
             if d.get("power_on_hours") is not None] or [None]),
        # Kept under the original name so one KB rule covers both device
        # families; `attribute_source` per disk says which sensor spoke.
        "any_reallocated": bool(failing or unhealthy),
        "max_pending_sectors": max(pending) if pending else 0,
        "max_wear_percent": max(wear) if wear else None,
        "min_available_spare_percent": min(
            [d["available_spare_percent"] for d in disks
             if d.get("available_spare_percent") is not None] or [None]),
    }


def collect():
    require_privilege("elevated")

    if not shutil.which("smartctl"):
        raise Skip("smartctl not installed")

    disks = _physical_disks()
    if not disks:
        raise Skip("no physical disk devices found")

    results = []
    for disk in disks:
        try:
            # `-a`, not `-H -A`. The composite temperature thresholds a
            # drive publishes live in the INFORMATION section, which
            # `-H -A` does not include — so parsing that output yielded
            # a null threshold, `over_temperature` was permanently
            # False, and the rule reading it could never fire. The same
            # silent-null failure as the ATA-only parsing, one layer up.
            #
            # `-a` may exit non-zero when an optional log is unreadable
            # (a Crucial P3 advertises Self_Test and then rejects the
            # self-test log). The return code is deliberately not
            # checked: the health data we need is present regardless,
            # and treating a missing optional log as a collector failure
            # would report a healthy drive as unchecked.
            proc = subprocess.run(
                ["smartctl", "-a", disk],
                capture_output=True, text=True, timeout=25,
            )
        except subprocess.TimeoutExpired:
            results.append({"device": disk, "status": "timeout", "health": "unknown"})
            continue
        results.append(parse_disk(disk, proc.stdout))

    return summarise(results)
