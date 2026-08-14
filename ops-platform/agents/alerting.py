"""Alert delivery — the path from "the guard found something" to a human.

Lives under `agents/` for the same reason `patrolling.py` and
`capturing.py` do: more than one caller needs it, and platform skill files
must never import one another (that collision was a live outage).

**Why this module exists at all.** Until 2026-07-26 alerts were handed to
`send_security_alert` in the vendored fork. The fork was archived; nothing
replaced it; `should_alert` went on computing correctly and the answer
reached no one for a day. There was no error, because there was no code
left to fail. This module is the replacement, and its design is shaped
entirely by that failure:

- **Every channel returns a `Delivery`, always.** Nothing is fire-and-forget.
- **"Not configured" is reported, not treated as fine.** A channel the
  operator never set up must never resemble a channel that worked.
- **A total delivery failure is loud.** If nothing carried the alert, the
  caller is told in those words.
- **The journal is written first and unconditionally.** Networks fail, and
  they fail hardest when the LAN is under attack — which is when alerts
  matter. The on-disk record is the thing that must never depend on a
  socket.

The registered administrator lives in `data/admin.json` (gitignored). Who
gets told is a fact the operator can read, not a constant buried in code.
"""

import json
import os
from datetime import datetime
from typing import List, Optional

from contracts.alert import (
    DELIVERED, FAILED, SKIPPED, SUPPRESSED, Alert, Delivery, summarize,
)
from domains.alerting import DEFAULT_MIN_SEVERITY, build_alert, should_deliver
from engines import notify_desktop, notify_ntfy, notify_smtp, secret_file

ADMIN_PATH = os.path.join("data", "admin.json")
ALERT_LOG = os.path.join("data", "census", "alerts.log")


# --- the registered administrator ----------------------------------------

DEFAULT_ADMIN = {
    "name": "",
    "min_severity": DEFAULT_MIN_SEVERITY,
    "quiet_hours": {"start": None, "end": None},
    "desktop": {"enabled": True},
    "ntfy": {"enabled": False, "topic": "", "server": notify_ntfy.DEFAULT_SERVER,
             "allow_insecure": False},
    "email": {"enabled": False, "host": "", "port": notify_smtp.DEFAULT_PORT,
              "to": "", "from": "", "username": "", "password_env": "HUGINN_SMTP_PASSWORD",
              "password_file": os.path.join("data", "secrets", "smtp.key")},
}


def load_admin(path: str = ADMIN_PATH) -> dict:
    """Read the registered administrator. Never raises; missing is a state.

    A missing or unreadable config is NOT an error that stops a patrol — it
    means nobody is registered, which `describe()` and the delivery result
    both say plainly. Failing the patrol because alerting is unconfigured
    would trade a working detector for a missing notification.
    """
    config = json.loads(json.dumps(DEFAULT_ADMIN))       # deep copy
    try:
        with open(path, encoding="utf-8") as handle:
            loaded = json.load(handle)
    except (OSError, ValueError):
        return config
    if not isinstance(loaded, dict):
        return config
    for key, value in loaded.items():
        if isinstance(value, dict) and isinstance(config.get(key), dict):
            config[key].update(value)
        else:
            config[key] = value
    return config


def _password(email_cfg: dict) -> str:
    """SMTP password from env first, then a gitignored file. Never logged."""
    from_env = os.environ.get(email_cfg.get("password_env") or "", "")
    if from_env.strip():
        return from_env.strip()
    try:
        with open(email_cfg.get("password_file") or "", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return ""


def configured_channels(admin: dict) -> List[str]:
    """Which channels are switched on. Used by `describe` and the tests."""
    names = []
    if (admin.get("desktop") or {}).get("enabled"):
        names.append(notify_desktop.NAME)
    if (admin.get("ntfy") or {}).get("enabled"):
        names.append(notify_ntfy.NAME)
    if (admin.get("email") or {}).get("enabled"):
        names.append(notify_smtp.NAME)
    return names


# --- delivery -------------------------------------------------------------

def _record(alert: Alert, deliveries, path: str = ALERT_LOG) -> Delivery:
    """Append the alert and its outcome to the on-disk log.

    Written even when every network channel fails, because this is the one
    record that does not depend on the network being trustworthy.
    """
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        entry = {
            "raised_at": alert.raised_at, "machine": alert.machine,
            "severity": alert.severity, "title": alert.title,
            "finding_count": alert.finding_count,
            "finding_ids": alert.finding_ids,
            "delivery": [{"channel": d.channel, "outcome": d.outcome,
                          "detail": d.detail, "target": d.target}
                         for d in deliveries],
        }
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return Delivery("journal", DELIVERED, "", path)
    except OSError as exc:
        return Delivery("journal", FAILED, str(exc), path)


def _plan(alert: Alert, admin: dict, engines: dict):
    """(channel name, enabled, zero-arg sender) for each channel, in order."""
    desktop = engines.get("desktop", notify_desktop)
    ntfy = engines.get("ntfy", notify_ntfy)
    smtp = engines.get("email", notify_smtp)
    ntfy_cfg = admin.get("ntfy") or {}
    mail_cfg = admin.get("email") or {}

    return (
        (notify_desktop.NAME,
         bool((admin.get("desktop") or {}).get("enabled")),
         lambda: desktop.send(alert)),
        (notify_ntfy.NAME,
         bool(ntfy_cfg.get("enabled")),
         lambda: ntfy.send(alert,
                           topic=ntfy_cfg.get("topic", ""),
                           server=ntfy_cfg.get("server", notify_ntfy.DEFAULT_SERVER),
                           allow_insecure=bool(ntfy_cfg.get("allow_insecure")))),
        (notify_smtp.NAME,
         bool(mail_cfg.get("enabled")),
         lambda: smtp.send(alert,
                           host=mail_cfg.get("host", ""),
                           to_address=mail_cfg.get("to", ""),
                           from_address=mail_cfg.get("from", ""),
                           port=int(mail_cfg.get("port", notify_smtp.DEFAULT_PORT)),
                           username=mail_cfg.get("username", ""),
                           password=_password(mail_cfg))),
    )


def deliver(alert: Alert, admin: Optional[dict] = None, now: Optional[datetime] = None,
            engines=None, log_path: str = ALERT_LOG) -> List[Delivery]:
    """Hand the alert to every configured channel. Returns one result each.

    `engines` is injectable so tests never touch a desktop, a socket or a
    mail server.
    """
    admin = admin if admin is not None else load_admin()
    now = now or datetime.now()
    quiet = admin.get("quiet_hours") or {}
    allowed = should_deliver(alert, now, quiet.get("start"), quiet.get("end"))

    results: List[Delivery] = []
    for name, enabled, sender in _plan(alert, admin, engines or {}):
        if not enabled:
            results.append(Delivery(name, SKIPPED, "not enabled in data/admin.json"))
        elif not allowed:
            results.append(Delivery(name, SUPPRESSED, "quiet hours (not critical)"))
        else:
            try:
                results.append(sender())
            except Exception as exc:                # noqa: BLE001
                # An engine that raised despite promising not to. Recorded as
                # a failure rather than allowed to abort the patrol: a broken
                # notifier must not take the detector down with it.
                results.append(Delivery(name, FAILED, f"{type(exc).__name__}: {exc}"))

    results.insert(0, _record(alert, results, log_path))
    return results


def raise_alert(findings, machine: str, admin: Optional[dict] = None,
                now: Optional[datetime] = None, engines=None,
                log_path: str = ALERT_LOG):
    """Findings in, (alert, deliveries) out. `(None, [])` if none qualify.

    None means "nothing worth interrupting anyone for" — never "nothing
    happened". The findings are in the journal and the timeline regardless.
    """
    admin = admin if admin is not None else load_admin()
    now = now or datetime.now()
    alert = build_alert(findings, machine, now,
                        min_severity=admin.get("min_severity", DEFAULT_MIN_SEVERITY))
    if alert is None:
        return None, []
    return alert, deliver(alert, admin, now, engines, log_path)


def render_delivery(alert: Optional[Alert], deliveries) -> str:
    """Human-readable outcome, for the patrol summary and the console."""
    if alert is None:
        return ""
    deliveries = list(deliveries or [])
    line = summarize(deliveries)
    carried = [d for d in deliveries if d.ok and d.channel != "journal"]
    if not carried:
        return (f"  ALERT RAISED, NOT DELIVERED — {line}\n"
                f"  It is recorded on disk; no channel reached a person.")
    return f"  Alert delivered — {line}"


# --- editing the administrator from the GUI -------------------------------
#
# The console writes these settings, so two rules apply that do not apply to
# hand-editing the file:
#
# 1. **The SMTP password never enters admin.json.** It goes to
#    `data/secrets/smtp.key` at mode 0600. admin.json is the kind of file a
#    person pastes into a chat window when asking for help; the password
#    must not travel with it.
# 2. **`redact()` is what leaves the machine.** A GET returns whether a
#    secret is set, never its value — so a browser tab, a screenshot or a
#    devtools panel cannot show the ntfy topic or the mail password.

SECRET_DIR = os.path.join("data", "secrets")
SMTP_KEY_PATH = os.path.join(SECRET_DIR, "smtp.key")

#: Fields the console may write. Anything else in a POST is ignored rather
#: than merged: an endpoint with no authentication (loopback-only, by the
#: standing decision) should have the smallest surface that does the job.
EDITABLE = {
    "name": str,
    "min_severity": str,
}


def redact(admin: dict) -> dict:
    """The safe-to-display view: secrets become booleans."""
    ntfy = dict(admin.get("ntfy") or {})
    mail = dict(admin.get("email") or {})
    topic = ntfy.pop("topic", "") or ""
    mail.pop("password_env", None)
    mail.pop("password_file", None)
    return {
        "name": admin.get("name", ""),
        "min_severity": admin.get("min_severity", DEFAULT_MIN_SEVERITY),
        "quiet_hours": dict(admin.get("quiet_hours") or {"start": None, "end": None}),
        "desktop": {"enabled": bool((admin.get("desktop") or {}).get("enabled"))},
        "ntfy": {
            "enabled": bool(ntfy.get("enabled")),
            "server": ntfy.get("server", notify_ntfy.DEFAULT_SERVER),
            "allow_insecure": bool(ntfy.get("allow_insecure")),
            "topic_set": bool(topic),
            "topic_hint": (topic[:6] + "…") if topic else "",
        },
        "email": {
            "enabled": bool(mail.get("enabled")),
            "host": mail.get("host", ""),
            "port": int(mail.get("port", notify_smtp.DEFAULT_PORT) or 0),
            "to": mail.get("to", ""),
            "from": mail.get("from", ""),
            "username": mail.get("username", ""),
            "password_set": bool(_password(admin.get("email") or {})),
        },
    }


def _write_secret(value: str, path: str = SMTP_KEY_PATH) -> None:
    """Write a credential owner-only from the moment it exists.

    `0o600` is the whole guarantee on POSIX. On Windows it is nearly a
    no-op — it toggles the read-only attribute and leaves the ACL inherited
    — so the file is additionally handed to `secret_file.restrict_to_owner`,
    which strips inheritance via `icacls`. That step is best-effort and
    never raises: a saved-but-less-restricted secret beats a secret the
    operator thinks was saved and was not.
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(value.strip() + "\n")
    os.chmod(path, 0o600)                      # in case the file pre-existed
    secret_file.restrict_to_owner(path)        # POSIX: no-op; Windows: icacls


def _quiet(value) -> Optional[int]:
    """An hour 0-23, or None. Anything unparseable disables the window.

    Failing to None rather than to 0 matters: hour 0 is a real quiet-hours
    boundary, so a typo interpreted as 0 would silently create a window
    nobody asked for. None mutes nothing, which is the safe direction.
    """
    try:
        hour = int(value)
    except (TypeError, ValueError):
        return None
    return hour if 0 <= hour <= 23 else None


def _apply_ntfy(admin: dict, incoming: dict) -> None:
    """Merge the ntfy section. A blank topic KEEPS the stored one."""
    admin["ntfy"]["enabled"] = bool(incoming.get("enabled"))
    admin["ntfy"]["allow_insecure"] = bool(incoming.get("allow_insecure"))
    if str(incoming.get("server") or "").strip():
        admin["ntfy"]["server"] = incoming["server"].strip()
    if str(incoming.get("topic") or "").strip():
        admin["ntfy"]["topic"] = incoming["topic"].strip()


def _apply_email(admin: dict, incoming: dict, secret_path: str) -> None:
    """Merge the email section. A blank password KEEPS the stored one."""
    admin["email"]["enabled"] = bool(incoming.get("enabled"))
    for field in ("host", "to", "from", "username"):
        if field in incoming:
            admin["email"][field] = str(incoming.get(field) or "").strip()
    if str(incoming.get("port") or "").strip():
        try:
            admin["email"]["port"] = int(incoming["port"])
        except (TypeError, ValueError):
            pass                              # keep the previous port
    if str(incoming.get("password") or "").strip():
        _write_secret(incoming["password"], secret_path)
        # Record WHERE it went. Without this the secret is written to
        # `secret_path` while the config still names the default, so
        # `_password()` reads a file that does not hold it and every later
        # check reports "no password set" — a credential that exists on disk
        # and is invisible to the code that needs it. At the default path
        # the two already agree; anywhere else it is the difference between
        # working and not.
        admin["email"]["password_file"] = secret_path


def save_admin(patch: dict, path: str = ADMIN_PATH,
               secret_path: str = SMTP_KEY_PATH) -> dict:
    """Merge `patch` into the stored administrator. Returns the redacted result.

    Only known fields are taken. Blank secrets mean "leave what is there" —
    otherwise the console, which never receives the current secret, would
    erase it on every save.
    """
    admin = load_admin(path)
    patch = patch or {}

    for key, caster in EDITABLE.items():
        if key in patch:
            admin[key] = caster(patch[key])

    quiet = patch.get("quiet_hours") or {}
    if "start" in quiet or "end" in quiet:
        admin["quiet_hours"] = {"start": _quiet(quiet.get("start")),
                                "end": _quiet(quiet.get("end"))}

    if "desktop" in patch:
        admin["desktop"]["enabled"] = bool(patch["desktop"].get("enabled"))

    if "ntfy" in patch:
        _apply_ntfy(admin, patch["ntfy"])
    if "email" in patch:
        _apply_email(admin, patch["email"], secret_path)

    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(admin, handle, indent=2, ensure_ascii=False)
    os.replace(tmp, path)
    return redact(admin)
