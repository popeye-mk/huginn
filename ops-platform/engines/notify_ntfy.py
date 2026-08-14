"""ntfy push engine — a notification that reaches a phone.

The first deliberate outbound connection this product makes. That was a
decision, taken 2026-07-27 and recorded in NEXT-CHAPTER.md item 2: an
alert the operator cannot receive while away from the machine is not much
of an alert.

Two properties keep the cost of it low. No password is stored — the topic
name is the only secret, and a self-hosted ntfy needs no account at all.
And HTTPS is required by default, because the moment this channel matters
most is the moment the LAN is compromised, and an alert saying "your
gateway MAC changed" travelling in plaintext across that same LAN tells
the attacker they have been seen.

Engine-layer because it opens a socket.
"""

import json
import urllib.error
import urllib.request
from typing import Optional

from contracts.alert import DELIVERED, FAILED, SKIPPED, Delivery

NAME = "ntfy"
DEFAULT_SERVER = "https://ntfy.sh"
DEFAULT_TIMEOUT = 15

#: ntfy priority 1-5. Critical gets 5 (bypasses most phone quiet modes),
#: warning 4, everything else 3.
#:
#: **These are ints, not strings, and that distinction cost a live failure.**
#: The first version sent `"priority": "4"`. ntfy's JSON API types the field
#: as a number and rejects the whole request with HTTP 400 — so the very
#: first real alert to a real phone was refused. The header form
#: (`X-Priority: 4`) does take a string, which is what made the mistake easy.
_PRIORITY = {"critical": 5, "warning": 4, "info": 3}


def _explain(exc) -> str:
    """ntfy's own reason for rejecting a request, short and safe to log.

    Never raises: this runs inside an exception handler, and a diagnostic
    that throws while explaining a failure would replace a useful message
    with a useless one.
    """
    try:
        raw = exc.read().decode("utf-8", "replace").strip()
    except Exception:                               # noqa: BLE001
        return "no detail returned"
    if not raw:
        return "no detail returned"
    try:
        body = json.loads(raw)
        if isinstance(body, dict):
            reason = body.get("error") or body.get("message") or ""
            link = body.get("link") or ""
            return (f"{reason} {link}".strip() or raw)[:180]
    except ValueError:
        pass
    return raw[:180]


def _target(server: str, topic: str) -> str:
    """A loggable destination. The topic IS the secret, so it is masked."""
    shown = (topic[:4] + "…") if len(topic) > 4 else "…"
    return f"{server.rstrip('/')}/{shown}"


def send(alert, topic: str, server: str = DEFAULT_SERVER,
         allow_insecure: bool = False, opener=None,
         timeout: int = DEFAULT_TIMEOUT) -> Delivery:
    """POST the alert to an ntfy topic. `opener` is injectable for tests."""
    if not topic:
        return Delivery(NAME, SKIPPED, "no topic configured", "")

    server = (server or DEFAULT_SERVER).rstrip("/")
    target = _target(server, topic)

    if not server.startswith("https://") and not allow_insecure:
        # Refuse rather than silently downgrade. A plaintext alert channel
        # is worse than a missing one: it looks like protection while
        # broadcasting the finding to whoever is on the wire.
        return Delivery(NAME, FAILED,
                        "server is not https (set allow_insecure only for a "
                        "self-hosted ntfy on a trusted link)", target)

    payload = json.dumps({
        "topic": topic,
        "title": f"Huginn — {alert.machine}",
        "message": alert.body,
        "priority": _PRIORITY.get((alert.severity or "").strip().lower(), 3),
        "tags": ["warning"] if alert.is_critical else ["mag"],
    }).encode("utf-8")

    request = urllib.request.Request(
        server, data=payload, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "huginn/1.0"},
    )
    try:
        with (opener or urllib.request.urlopen)(request, timeout=timeout) as response:
            code = getattr(response, "status", 200)
        if 200 <= int(code) < 300:
            return Delivery(NAME, DELIVERED, "", target)
        return Delivery(NAME, FAILED, f"HTTP {code}", target)
    except urllib.error.HTTPError as exc:
        # Read the body. ntfy answers a rejected request with JSON saying
        # exactly what was wrong ("invalid priority", "invalid topic"), and
        # the first version of this discarded it — reporting a bare
        # "HTTP 400" that told the operator a channel had failed and nothing
        # whatsoever about why. A failure you cannot act on is only half
        # reported.
        return Delivery(NAME, FAILED, f"HTTP {exc.code}: {_explain(exc)}", target)
    except urllib.error.URLError as exc:
        # The interesting case: this is what a compromised or dead network
        # looks like from here. It must read as a FAILED delivery, never
        # as "nothing to report".
        return Delivery(NAME, FAILED, f"unreachable: {exc.reason}", target)
    except Exception as exc:                        # noqa: BLE001
        return Delivery(NAME, FAILED, f"{type(exc).__name__}: {exc}", target)
