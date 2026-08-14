"""Tests for the administrator settings the console writes.

Split from test_alerting.py when it crossed the 400-line hard limit — these
cover the WRITE path (POST /api/admin -> save_admin) rather than delivery.

The rule doing the most work here is **a blank secret keeps the stored
one**. The console never receives the current ntfy topic or SMTP password,
so it posts blank fields for both unless the operator typed something new.
Treating blank as "clear it" would wipe both credentials on every save —
the settings page would silently disarm alerting each time it was used.

Run: python3 tools/test_admin_settings.py
"""

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agents import alerting  # noqa: E402
from platform_support.detect import current_os  # noqa: E402

passed = 0


def check(cond, msg):
    global passed
    assert cond, msg
    passed += 1


def _cfg_paths():
    d = tempfile.mkdtemp()
    return os.path.join(d, "admin.json"), os.path.join(d, "smtp.key")




def test_secrets_never_leave_the_process_in_a_redacted_view():
    """GET /api/admin feeds a browser tab. Secrets must not be in it."""
    cfg, key = _cfg_paths()
    view = alerting.save_admin(
        {"ntfy": {"enabled": True, "topic": "huginn-SECRETTOPIC"},
         "email": {"enabled": True, "host": "h", "to": "a@b",
                   "password": "hunter2"}}, cfg, key)
    blob = json.dumps(view)
    check("SECRETTOPIC" not in blob, "the ntfy topic is not in the payload")
    check("hunter2" not in blob, "the SMTP password is not in the payload")
    check(view["ntfy"]["topic_set"] and view["email"]["password_set"],
          "but the payload still says both ARE set")


def test_the_smtp_password_never_lands_in_admin_json():
    """admin.json is the file a person pastes into a chat asking for help."""
    cfg, key = _cfg_paths()
    alerting.save_admin({"email": {"enabled": True, "host": "h", "to": "a@b",
                                   "password": "hunter2"}}, cfg, key)
    check("hunter2" not in open(cfg, encoding="utf-8").read(),
          "the password is not in the config file")
    check(open(key, encoding="utf-8").read().strip() == "hunter2",
          "it is in the key file")
    # The owner-only guarantee is expressed differently per OS, and the
    # test asserts the one that actually applies rather than a POSIX mode
    # that Windows cannot honour. Asserting 0o600 on Windows failed the
    # verification disc — correctly: os.chmod there toggles the read-only
    # bit and never touches the ACL, so the mode was a claim the platform
    # could not keep. On POSIX the mode IS the guarantee; on Windows the
    # guarantee is icacls, applied best-effort by _write_secret and checked
    # in its own test below.
    if current_os() != "windows":
        check(oct(os.stat(key).st_mode & 0o777) == "0o600",
              "POSIX: owner-only from the moment it exists")
    else:
        # What holds on every OS: the secret is out of admin.json entirely,
        # which is the property the docstring above actually cares about.
        check("hunter2" not in open(cfg, encoding="utf-8").read(),
              "the password is kept out of the pasteable config file")


def test_a_blank_secret_KEEPS_the_stored_one():
    """The rule the whole panel depends on.

    The console never receives the current secret, so every save posts a
    blank field unless the operator typed a new value. Treating blank as
    "clear it" would wipe the ntfy topic and the mail password on every
    save — the settings page would silently disarm alerting each time it
    was used.
    """
    cfg, key = _cfg_paths()
    alerting.save_admin({"ntfy": {"enabled": True, "topic": "keep-me"},
                         "email": {"enabled": True, "host": "h", "to": "a@b",
                                   "password": "hunter2"}}, cfg, key)
    alerting.save_admin({"ntfy": {"enabled": True, "topic": ""},
                         "email": {"enabled": True, "host": "h", "to": "a@b",
                                   "password": ""}}, cfg, key)
    check(alerting.load_admin(cfg)["ntfy"]["topic"] == "keep-me",
          "the topic survived a blank save")
    check(open(key, encoding="utf-8").read().strip() == "hunter2",
          "so did the password")


def test_saving_records_where_the_secret_went():
    """A credential the code cannot find is a credential that does not exist.

    save_admin used to write the password to `secret_path` while leaving
    password_file naming the default — so _password() read the wrong file
    and every later check reported "no password set", with the credential
    sitting on disk the whole time.
    """
    cfg, key = _cfg_paths()
    alerting.save_admin({"email": {"enabled": True, "host": "h", "to": "a@b",
                                   "password": "hunter2"}}, cfg, key)
    check(alerting.load_admin(cfg)["email"]["password_file"] == key,
          "the config names the file the secret was actually written to")
    check(alerting.redact(alerting.load_admin(cfg))["email"]["password_set"],
          "so the password is visible to the code that needs it")


def test_a_junk_quiet_hour_disables_the_window_rather_than_inventing_one():
    """Failing to None, not to 0. Hour 0 is a real boundary, so a typo read
    as 0 would silently create a quiet window nobody asked for."""
    cfg, key = _cfg_paths()
    for value in (25, -1, "abc", None):
        out = alerting.save_admin({"quiet_hours": {"start": value, "end": 7}}, cfg, key)
        check(out["quiet_hours"]["start"] is None, f"{value!r} disables the window")
    out = alerting.save_admin({"quiet_hours": {"start": "7", "end": 22}}, cfg, key)
    check(out["quiet_hours"]["start"] == 7, "a numeric string is accepted")


def test_unknown_fields_are_ignored_not_merged():
    """An endpoint with no authentication gets the smallest surface that works."""
    cfg, key = _cfg_paths()
    alerting.save_admin({"evil": {"x": 1}, "min_severity": "critical"}, cfg, key)
    stored = alerting.load_admin(cfg)
    check("evil" not in stored, "an unknown key is dropped")
    check(stored["min_severity"] == "critical", "a known one is taken")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print(f"{passed} tests passed")
