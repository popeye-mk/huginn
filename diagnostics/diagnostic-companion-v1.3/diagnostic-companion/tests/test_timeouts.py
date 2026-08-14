"""Timeout layering (spec §3.3).

Every collector has two timeouts: the subprocess it spawns, and the
thread wrapper in cli.py that supervises it. They must not be equal and
the outer must be larger, for a reason that is easy to miss:

**A thread timeout cannot kill a subprocess.** `collectors/base.py`
uses ThreadPoolExecutor, and CPython cannot interrupt a blocked call in
another thread. When the outer timeout fires first, the collector is
*abandoned*, not terminated — the PowerShell process keeps running in
the background, holding whatever it was holding. Only the inner
subprocess timeout actually terminates anything.

Before this test, `network` and `logs` had inner timeouts LONGER than
their outer ones (15 vs 10), so their subprocess timeouts were
unreachable by construction. A real Windows VM under test load hit the
10s wall and reported `network - timeout` while the PowerShell query
carried on running.
"""

import importlib

import pytest

# (module, cli collector name). Imported by name so a renamed module
# fails loudly here rather than silently dropping out of coverage.
WINDOWS_COLLECTORS = [
    ("collectors.windows.system", "system"),
    ("collectors.windows.network", "network"),
    ("collectors.windows.disk", "disk"),
    ("collectors.windows.logs", "logs"),
    ("collectors.windows.battery", "battery"),
    ("collectors.windows.wifi", "wifi"),
    ("collectors.windows.smart", "smart"),
]

# Enough slack for process startup and teardown to happen inside the
# outer window rather than racing it.
MIN_HEADROOM_S = 3


def outer_timeouts():
    import cli
    return {name: timeout for name, _fn, timeout, _priv
            in cli.CORE_COLLECTORS + cli.OPTIONAL_COLLECTORS}


@pytest.mark.parametrize("module_name,collector", WINDOWS_COLLECTORS)
def test_outer_timeout_exceeds_the_subprocess_timeout(module_name, collector):
    module = importlib.import_module(module_name)
    inner = module.PS_TIMEOUT_S
    outer = outer_timeouts()[collector]

    assert outer > inner, (
        f"{collector}: outer timeout {outer}s does not exceed inner {inner}s. "
        "The thread wrapper would fire first and abandon the subprocess "
        "instead of terminating it."
    )
    assert outer - inner >= MIN_HEADROOM_S, (
        f"{collector}: only {outer - inner}s of headroom between the "
        f"subprocess timeout and its supervisor; too tight to be reliable."
    )


@pytest.mark.parametrize("module_name,_collector", WINDOWS_COLLECTORS)
def test_every_windows_collector_declares_its_timeout(module_name, _collector):
    """A collector without a declared timeout escapes the check above."""
    module = importlib.import_module(module_name)
    assert isinstance(module.PS_TIMEOUT_S, int)
    assert module.PS_TIMEOUT_S > 0


def test_network_gets_the_longest_core_budget():
    """Three DNS resolutions plus two pings is the slowest core check.

    A real Windows VM under load exceeded 10s here, which is what
    prompted the whole layering fix.
    """
    outer = outer_timeouts()
    assert outer["network"] > outer["system"]
    assert outer["network"] > outer["disk"]
    assert outer["network"] >= 30


def test_all_collectors_are_covered_by_this_module():
    """New collectors must be added here, or they skip the check."""
    import cli
    registered = {name for name, _f, _t, _p
                  in cli.CORE_COLLECTORS + cli.OPTIONAL_COLLECTORS}
    checked = {collector for _m, collector in WINDOWS_COLLECTORS}
    assert registered == checked, f"not timeout-checked: {registered ^ checked}"
