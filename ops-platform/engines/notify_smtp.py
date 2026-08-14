"""SMTP engine — a real email to the registered administrator.

Stdlib `smtplib` and `email`, so the zero-dependency property survives.

**This channel stores a password on the machine, and that is worth naming
out loud.** The operator of this box previously declined to give Huginn
the router's password; an SMTP app password is the same class of asset. It
is read from a gitignored file or the environment, never committed, never
logged, and never included in a `Delivery.detail` — but it is on disk, and
anyone who owns this host owns it. Prefer ntfy, which needs no password,
unless an archivable email is specifically wanted.

STARTTLS is required by default for the same reason ntfy requires HTTPS:
the moment this channel matters is the moment the network is hostile.

Engine-layer because it opens a socket.
"""

import smtplib
import ssl
from email.message import EmailMessage
from typing import Optional

from contracts.alert import DELIVERED, FAILED, SKIPPED, Delivery

NAME = "email"
DEFAULT_PORT = 587
DEFAULT_TIMEOUT = 30


def send(alert, host: str, to_address: str, from_address: str = "",
         port: int = DEFAULT_PORT, username: str = "", password: str = "",
         use_starttls: bool = True, transport=None,
         timeout: int = DEFAULT_TIMEOUT) -> Delivery:
    """Send the alert as email. `transport` is injectable for tests.

    A test never needs a mail server, and — more to the point — a test can
    assert that the password never reaches the returned Delivery.
    """
    if not host or not to_address:
        return Delivery(NAME, SKIPPED, "no SMTP host or recipient configured", "")

    target = to_address                     # safe to log; the password is not
    sender = from_address or username or f"huginn@{alert.machine}"

    message = EmailMessage()
    message["Subject"] = f"[Huginn] {alert.severity}: {alert.title}"[:250]
    message["From"] = sender
    message["To"] = to_address
    message.set_content(alert.body)

    try:
        (transport or _deliver)(
            message, host, port, username, password, use_starttls, timeout)
    except smtplib.SMTPAuthenticationError:
        # Named separately: the fix is a credential, not a network problem,
        # and conflating the two wastes the operator's time at exactly the
        # wrong moment.
        return Delivery(NAME, FAILED, "authentication rejected", target)
    except Exception as exc:                        # noqa: BLE001
        # str(exc) can echo the SMTP dialogue. It does not carry the
        # password (smtplib does not put it in exception text), but the type
        # plus a short reason is all anyone needs, and a short detail cannot
        # accidentally grow to include a credential later.
        return Delivery(NAME, FAILED, type(exc).__name__, target)
    return Delivery(NAME, DELIVERED, "", target)


def _deliver(message, host, port, username, password, use_starttls, timeout):
    with smtplib.SMTP(host, port, timeout=timeout) as server:
        if use_starttls:
            server.starttls(context=ssl.create_default_context())
        if username:
            server.login(username, password)
        server.send_message(message)
