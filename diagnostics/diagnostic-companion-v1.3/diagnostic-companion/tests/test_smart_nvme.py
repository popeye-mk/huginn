"""SMART parsing for both device families (spec §4.2).

ATA and NVMe expose entirely different health attributes. Parsing only
the ATA ones meant that on an NVMe drive — the type in most machines
built in the last several years — every failure indicator came back
null, `any_reallocated` was permanently False, and both SMART rules
could never fire. The collector reported "ok" and the report showed no
disk finding, which is indistinguishable from a healthy disk.

Found by running as root on a real laptop and reading the values. The
report gave no hint.
"""

import pytest

from collectors.optional.smart import parse_disk, parse_nvme, summarise

NVME_HEALTHY = """smartctl 7.2 2020-12-30 r5155 [x86_64-linux] (local build)

=== START OF SMART DATA SECTION ===
SMART overall-health self-assessment test result: PASSED

SMART/Health Information (NVMe Log 0x02)
Critical Warning:                   0x00
Temperature:                        35 Celsius
Available Spare:                    100%
Available Spare Threshold:          10%
Percentage Used:                    2%
Data Units Written:                 12,345,678
Media and Data Integrity Errors:    0
Error Information Log Entries:      12
"""

NVME_FAILING = """smartctl 7.2 2020-12-30 r5155 [x86_64-linux] (local build)

=== START OF SMART DATA SECTION ===
SMART overall-health self-assessment test result: PASSED

SMART/Health Information (NVMe Log 0x02)
Critical Warning:                   0x04
Temperature:                        61 Celsius
Available Spare:                    4%
Available Spare Threshold:          10%
Percentage Used:                    96%
Media and Data Integrity Errors:    47
Error Information Log Entries:      210
"""

ATA_HEALTHY = """smartctl 7.2 2020-12-30 r5155 [x86_64-linux] (local build)

=== START OF READ SMART DATA SECTION ===
SMART overall-health self-assessment test result: PASSED

ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  RAW_VALUE
  5 Reallocated_Sector_Ct   0x0033   100   100   036    Pre-fail  Always       0
197 Current_Pending_Sector  0x0012   100   100   000    Old_age   Always       0
"""

ATA_FAILING = ATA_HEALTHY.replace(
    "Pre-fail  Always       0", "Pre-fail  Always       184").replace(
    "Old_age   Always       0", "Old_age   Always       12")


# --- the regression --------------------------------------------------

def test_healthy_nvme_is_parsed_not_left_null():
    """The bug: every NVMe field came back null and read as healthy."""
    disk = parse_disk("/dev/nvme0n1", NVME_HEALTHY)

    assert disk["attribute_source"] == "nvme"
    assert disk["available_spare_percent"] == 100
    assert disk["percentage_used"] == 2
    assert disk["media_errors"] == 0
    assert disk["failing"] is False


def test_failing_nvme_is_detected():
    """Before the fix this drive was reported as perfectly fine."""
    disk = parse_disk("/dev/nvme0n1", NVME_FAILING)

    assert disk["failing"] is True
    assert disk["wear_percent"] == 96
    assert disk["available_spare_percent"] == 4
    assert summarise([disk])["any_reallocated"] is True


def test_nvme_health_passed_does_not_override_the_indicators():
    """A drive can report PASSED while its spare pool is nearly gone.

    Trusting the rolled-up verdict alone is exactly how a failing SSD
    reads as healthy right up until it doesn't.
    """
    disk = parse_disk("/dev/nvme0n1", NVME_FAILING)
    assert disk["health"] == "PASSED"
    assert disk["failing"] is True


@pytest.mark.parametrize("field,expected", [
    ("critical_warning", 4),
    ("available_spare_percent", 4),
    ("available_spare_threshold", 10),
    ("percentage_used", 96),
    ("media_errors", 47),
    ("error_log_entries", 210),
])
def test_every_nvme_field_is_extracted(field, expected):
    assert parse_nvme(NVME_FAILING)[field] == expected


def test_thousands_separators_in_counters_are_handled():
    """smartctl prints large counters as '12,345,678'."""
    output = NVME_HEALTHY.replace("Media and Data Integrity Errors:    0",
                                  "Media and Data Integrity Errors:    1,204")
    assert parse_nvme(output)["media_errors"] == 1204


# --- ATA still works -------------------------------------------------

def test_healthy_ata_unchanged():
    disk = parse_disk("/dev/sda", ATA_HEALTHY)
    assert disk["attribute_source"] == "ata"
    assert disk["reallocated_sectors"] == 0
    assert disk["failing"] is False


def test_failing_ata_detected():
    disk = parse_disk("/dev/sda", ATA_FAILING)
    assert disk["reallocated_sectors"] == 184
    assert disk["failing"] is True
    assert summarise([disk])["any_reallocated"] is True


def test_device_family_is_recorded_not_implied():
    """A report must not imply ATA precision from an NVMe sensor."""
    assert parse_disk("/dev/nvme0n1", NVME_HEALTHY)["attribute_source"] == "nvme"
    assert parse_disk("/dev/sda", ATA_HEALTHY)["attribute_source"] == "ata"


# --- aggregation ------------------------------------------------------

def test_mixed_fleet_of_disks_aggregates_correctly():
    disks = [parse_disk("/dev/sda", ATA_HEALTHY),
             parse_disk("/dev/nvme0n1", NVME_FAILING)]
    summary = summarise(disks)

    assert summary["any_reallocated"] is True
    assert summary["max_wear_percent"] == 96
    assert summary["min_available_spare_percent"] == 4


def test_all_healthy_disks_report_nothing():
    summary = summarise([parse_disk("/dev/sda", ATA_HEALTHY),
                         parse_disk("/dev/nvme0n1", NVME_HEALTHY)])
    assert summary["any_reallocated"] is False


def test_unknown_health_is_not_treated_as_failure():
    """A drive that reports nothing must not be called failing."""
    disk = parse_disk("/dev/sdb", "no smart data here")
    assert disk["health"] == "unknown"
    assert summarise([disk])["any_reallocated"] is False


def test_nvme_rules_fire_on_the_fixture():
    """End-to-end through the real KB."""
    import json
    import os
    from interpreter import evaluate

    path = os.path.join(os.path.dirname(__file__), "fixtures", "nvme_failing.json")
    with open(path, encoding="utf-8") as f:
        snapshot = json.load(f)

    fired = {f["id"] for f in evaluate(snapshot)[0]}
    assert "nvme_spare_low" in fired
    assert "nvme_wear_high" in fired


# --- the drive's threshold, not ours ----------------------------------

def test_devices_own_spare_threshold_is_used():
    """A real Acer NVMe publishes 5%, not the commonly-quoted 10%.

    Judging spare against a number chosen by the rule author would make
    the tool wrong on any drive that disagrees — and drives do disagree.
    """
    output = NVME_HEALTHY.replace("Available Spare Threshold:          10%",
                                  "Available Spare Threshold:          5%") \
                         .replace("Available Spare:                    100%",
                                  "Available Spare:                    7%")
    disk = parse_disk("/dev/nvme0n1", output)

    # 7% is below a hardcoded 10 but above this drive's stated 5.
    assert disk["spare_threshold_used"] == 5
    assert disk["spare_below_threshold"] is False
    assert disk["failing"] is False
    assert summarise([disk])["any_spare_below_threshold"] is False


def test_below_the_devices_own_threshold_is_flagged():
    output = NVME_HEALTHY.replace("Available Spare Threshold:          10%",
                                  "Available Spare Threshold:          5%") \
                         .replace("Available Spare:                    100%",
                                  "Available Spare:                    3%")
    disk = parse_disk("/dev/nvme0n1", output)

    assert disk["spare_below_threshold"] is True
    assert disk["failing"] is True
    assert summarise([disk])["any_spare_below_threshold"] is True


def test_missing_threshold_falls_back_without_crashing():
    """Rare, but a drive may not publish a threshold at all."""
    output = NVME_HEALTHY.replace("Available Spare Threshold:          10%\n", "") \
                         .replace("Available Spare:                    100%",
                                  "Available Spare:                    4%")
    disk = parse_disk("/dev/nvme0n1", output)
    assert disk["spare_threshold_used"] == 10  # documented fallback
    assert disk["spare_below_threshold"] is True


def test_ata_disks_never_report_a_spare_concept():
    disk = parse_disk("/dev/sda", ATA_HEALTHY)
    assert disk["spare_below_threshold"] is False
    assert summarise([disk])["any_spare_below_threshold"] is False


# --- counters, locale formatting, and derived signals -----------------

ACER_P3 = """smartctl 7.4 2023-08-01 r5530 [x86_64-linux] (local build)

=== START OF INFORMATION SECTION ===
Model Number:                       CT1000P3PSSD8
Warning  Comp. Temp. Threshold:     83 Celsius
Critical Comp. Temp. Threshold:     85 Celsius

=== START OF SMART DATA SECTION ===
SMART overall-health self-assessment test result: PASSED

SMART/Health Information (NVMe Log 0x02)
Critical Warning:                   0x00
Temperature:                        31 Celsius
Available Spare:                    100%
Available Spare Threshold:          5%
Percentage Used:                    3%
Data Units Written:                 36.958.500 [18,9 TB]
Power Cycles:                       708
Power On Hours:                     1.098
Unsafe Shutdowns:                   95
Media and Data Integrity Errors:    0
Error Information Log Entries:      0
"""


def test_locale_thousands_separators_are_parsed_as_integers():
    """smartctl formats counters using the system locale.

    A Dutch or German install prints "1.098" for 1098. Parsing that as a
    float would report a drive with 1098 power-on hours as having 1.098 —
    a thousand-fold error in the machine's favour.
    """
    disk = parse_disk("/dev/nvme0n1", ACER_P3)
    assert disk["power_on_hours"] == 1098
    assert disk["power_cycles"] == 708
    assert disk["unsafe_shutdowns"] == 95


def test_unsafe_shutdown_ratio_uses_the_denominator():
    """95 unsafe shutdowns means nothing without the number of boots."""
    disk = parse_disk("/dev/nvme0n1", ACER_P3)
    assert disk["unsafe_shutdown_ratio"] == pytest.approx(0.134, abs=0.001)


def test_ratio_is_suppressed_on_a_machine_with_too_few_boots():
    """1 of 3 boots is 33% and tells you nothing.

    Reporting it would let the rule fire on a nearly-new machine.
    """
    output = ACER_P3.replace("Power Cycles:                       708",
                             "Power Cycles:                       3") \
                    .replace("Unsafe Shutdowns:                   95",
                             "Unsafe Shutdowns:                   1")
    disk = parse_disk("/dev/nvme0n1", output)
    assert disk["unsafe_shutdown_ratio"] is None
    assert summarise([disk])["max_unsafe_shutdown_ratio"] is None


def test_temperature_uses_the_drives_own_warning_threshold():
    """Vendors publish different limits; 31 C is nowhere near 83."""
    disk = parse_disk("/dev/nvme0n1", ACER_P3)
    assert disk["temperature_c"] == 31
    assert disk["warning_temp_threshold"] == 83
    assert disk["over_temperature"] is False


def test_over_temperature_detected_against_the_published_limit():
    output = ACER_P3.replace("Temperature:                        31 Celsius",
                             "Temperature:                        84 Celsius")
    disk = parse_disk("/dev/nvme0n1", output)
    assert disk["over_temperature"] is True
    assert summarise([disk])["any_over_temperature"] is True


def test_a_drive_without_temperature_data_is_not_called_hot():
    output = ACER_P3.replace("Temperature:                        31 Celsius\n", "")
    disk = parse_disk("/dev/nvme0n1", output)
    assert disk["over_temperature"] is False


def test_new_rules_fire_on_the_fixture():
    import json
    import os
    from interpreter import evaluate

    path = os.path.join(os.path.dirname(__file__), "fixtures", "nvme_hot_unclean.json")
    with open(path, encoding="utf-8") as f:
        snapshot = json.load(f)

    findings, worth_checking, _ = evaluate(snapshot)

    assert "nvme_over_temperature" in {f["id"] for f in findings}
    # A symptom with several causes must never headline (§3.5).
    assert "unsafe_shutdown_rate_high" in {f["id"] for f in worth_checking}
    assert "unsafe_shutdown_rate_high" not in {f["id"] for f in findings}


def test_temperature_threshold_comes_from_the_information_section():
    """Regression: the collector ran `smartctl -H -A`.

    The composite temperature thresholds are printed in the INFORMATION
    section, which `-H -A` omits. The threshold parsed as null, so
    over_temperature was permanently False and the rule reading it could
    never fire — on any drive.
    """
    disk = parse_disk("/dev/nvme0n1", ACER_P3)
    assert disk["warning_temp_threshold"] == 83
    assert disk["critical_temp_threshold"] == 85


def test_missing_threshold_is_reported_not_silently_false():
    """"Not hot" and "could not tell" must be distinguishable."""
    output = ACER_P3.replace("Warning  Comp. Temp. Threshold:     83 Celsius\n", "")
    disk = parse_disk("/dev/nvme0n1", output)

    assert disk["over_temperature"] is False
    assert "temperature_unavailable" in disk


def test_temperature_available_means_no_caveat():
    disk = parse_disk("/dev/nvme0n1", ACER_P3)
    assert "temperature_unavailable" not in disk


def test_collector_requests_the_full_smart_output():
    """The invocation itself is the bug surface, so assert on it."""
    import inspect
    from collectors.optional import smart

    source = inspect.getsource(smart.collect)
    assert '"-a"' in source, "must request the full output, not just -H -A"
    assert '"-H", "-A"' not in source
