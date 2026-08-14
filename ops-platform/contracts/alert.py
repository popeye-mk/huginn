"""Alert contracts — what gets sent, and what happened when it was.

Two types, and the second matters more than it looks.

`Alert` is what the guard decided is worth a human's attention. `Delivery`
is the per-channel outcome of trying to hand it over — and it exists as a
first-class result, rather than a boolean or a swallowed exception,
because of how this whole chapter started: the fork bridge that used to
carry alerts was archived, `should_alert` went on computing correctly, and
nobody was ever told. Nothing raised. Nothing logged. The failure was
invisible precisely because delivery had no representation.

So a send that fails produces a `Delivery` saying so, and a channel that
was never configured produces a `Delivery` saying *that* — because
"skipped" is not "delivered", and a channel nobody set up must never look
like a channel that worked.
"""

from dataclasses import dataclass, field
from typing import List, Optional

#: Ordered least to most urgent. Anything not in here is treated as more
#: urgent than everything in here — an unrecognised severity should start
#: by being noticed, not filed under "probably fine".
SEVERITY_ORDER = ("info", "warning", "critical")

#: Outcomes of trying to deliver on one channel.
DELIVERED = "delivered"
FAILED = "failed"
SKIPPED = "skipped"          # not configured — NEVER a success
SUPPRESSED = "suppressed"    # configured, deliberately held (quiet hours)


@dataclass(frozen=True)
class Alert:
    """One thing worth telling the administrator about."""

    machine: str
    severity: str
    title: str
    body: str
    raised_at: str
    finding_ids: List[str] = field(default_factory=list)
    #: How many findings this alert stands for, including any not spelled
    #: out in `body`. Kept separate from len(finding_ids) so a truncated
    #: message can still state the true total.
    finding_count: int = 0

    @property
    def is_critical(self) -> bool:
        return self.severity.strip().lower() == "critical"


@dataclass(frozen=True)
class Delivery:
    """What happened on one channel. Honest about every outcome."""

    channel: str
    outcome: str
    detail: str = ""
    #: Where it went, with secrets already removed. Safe to log and to
    #: print in the console — an alert channel that leaked its own
    #: credentials into the journal would be a worse bug than silence.
    target: str = ""

    @property
    def ok(self) -> bool:
        return self.outcome == DELIVERED

    @property
    def needs_attention(self) -> bool:
        """A configured channel that did not carry the alert.

        `SKIPPED` is excluded: not configuring SMTP is a choice, not a
        fault. `FAILED` is included even when another channel succeeded,
        because a channel you believe is working and is not is exactly
        the assumption this module exists to prevent.
        """
        return self.outcome == FAILED


def summarize(deliveries) -> str:
    """One line stating which channels carried the alert and which did not.

    Written for a log a tired person skims. It always names the failures
    explicitly rather than reporting a count of successes, because "2
    delivered" reads like success even when the third channel — the one
    that reaches the phone — is the one that broke.
    """
    deliveries = list(deliveries or [])
    if not deliveries:
        return "no channels attempted — the alert was NOT delivered to anyone"

    done = [d.channel for d in deliveries if d.ok]
    failed = [f"{d.channel} ({d.detail})" if d.detail else d.channel
              for d in deliveries if d.outcome == FAILED]
    held = [d.channel for d in deliveries if d.outcome == SUPPRESSED]
    skipped = [d.channel for d in deliveries if d.outcome == SKIPPED]

    parts = []
    parts.append("delivered: " + (", ".join(done) if done else "NONE"))
    if failed:
        parts.append("FAILED: " + ", ".join(failed))
    if held:
        parts.append("held (quiet hours): " + ", ".join(held))
    if skipped:
        parts.append("not configured: " + ", ".join(skipped))
    return "; ".join(parts)
