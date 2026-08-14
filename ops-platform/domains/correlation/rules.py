"""Correlation rules — which findings, together, mean something new.

Every rule here fires on finding IDs that **exist in the shipped
engines today**. None is written against a signal we hope to have later:
a rule that can never fire is worse than no rule, because it makes the
rule set look richer than it is.

Three deliberate constraints, each learned from the source tools:

**Rules name IDs, never match on wording.** Rule text gets reworded; an
ID is a contract. Text matching would silently reclassify findings the
day someone improves a sentence.

**Escalation must be earned.** A rule may only claim what its members
already support — the `Correlation` contract enforces the caps, but the
rules are written not to test them. If a story needs a louder claim than
its parts, the story is wrong.

**Suppression counts as correlation.** A rule that says *"this alert is
explained, don't chase it"* saves more of a solo admin's evening than
one that raises an alarm. Two of the four rules below do exactly that.
"""

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from contracts import Correlation, Finding
from contracts.citation import NOT_REQUESTED


@dataclass(frozen=True)
class CorrelationRule:
    """One 'these are the same story' rule."""

    id: str
    requires: Tuple[str, ...]          # finding IDs that must all be present
    severity: str
    confidence: str
    story: str
    suggested_action: Optional[str] = None
    suppresses: Tuple[str, ...] = ()
    # Optional extra gate for rules that need more than co-presence.
    guard: Optional[Callable[[Dict[str, Finding]], bool]] = None

    def matches(self, by_id: Dict[str, Finding]) -> bool:
        if not all(fid in by_id for fid in self.requires):
            return False
        return self.guard(by_id) if self.guard else True

    def build(
        self,
        by_id: Dict[str, Finding],
        machine_id: str,
        citations: Tuple = (),
        grounding: str = NOT_REQUESTED,
    ) -> Correlation:
        members = [by_id[fid] for fid in self.requires]
        # Confidence is capped at the weakest member rather than asserted:
        # the rule states an intent, the data decides what is defensible.
        weakest = _weakest_confidence(members)
        return Correlation(
            id=self.id,
            machine_id=machine_id,
            story=self.story,
            members=members,
            severity=self.severity,
            confidence=_weaker_of(self.confidence, weakest),
            suggested_action=self.suggested_action,
            suppresses=self.suppresses,
            citations=tuple(citations),
            grounding=grounding,
        )

    @property
    def kb_query(self) -> str:
        """Fallback search text when no entry is keyed to this rule.

        The rule id is deliberately excluded — an id is a token, not
        meaning, and embedding one let a record win on a shared substring
        during R3. The story is what the entry should actually match.
        """
        return self.story


_CONFIDENCE_ORDER = ("certain", "likely", "possible")


def _weakest_confidence(members: List[Finding]) -> str:
    return max(
        (m.confidence for m in members),
        key=lambda c: _CONFIDENCE_ORDER.index(c),
    )


def _weaker_of(a: str, b: str) -> str:
    return a if _CONFIDENCE_ORDER.index(a) >= _CONFIDENCE_ORDER.index(b) else b


# --------------------------------------------------------------------------
# The rules
# --------------------------------------------------------------------------

RULES: Tuple[CorrelationRule, ...] = (

    # --- the security story the platform exists to tell -------------------
    CorrelationRule(
        id="poisoning_surface_actively_reachable",
        requires=("hygiene_poisoning_surface", "dns_resolution_failure"),
        severity="critical",
        confidence="likely",
        story=(
            "Name-resolution fallback (LLMNR/NetBIOS) is enabled AND normal "
            "DNS is currently failing. These are usually reported as two "
            "separate items, but together they are one situation: the "
            "fallback is not a dormant misconfiguration right now — DNS "
            "failure is exactly the trigger that makes this machine "
            "broadcast name queries to the whole local network, which is "
            "what a Responder-style credential capture listens for."
        ),
        suggested_action=(
            "Treat the DNS outage as urgent, and disable LLMNR/NetBIOS-NS "
            "regardless of the outcome — the exposure is only harmless "
            "while name resolution works."
        ),
    ),

    # --- the claim the whole platform was pitched on ----------------------
    CorrelationRule(
        id="compromise_pattern_load_and_c2",
        requires=("load_average_high", "threat_outbound_c2"),
        severity="critical",
        confidence="likely",
        story=(
            "This machine is working unusually hard AND is talking to an "
            "address a threat feed lists as a botnet command-and-control "
            "server. Either finding alone is ordinary — machines get busy, "
            "and feeds carry false positives. Together they are the "
            "signature of a host doing work it was not asked to do and "
            "reporting to somewhere it should not: mining, encrypting, or "
            "waiting for instructions. No single tool on this machine sees "
            "both halves, which is the entire reason this one exists."
        ),
        suggested_action=(
            "Treat as a suspected compromise until shown otherwise. Identify "
            "the process holding the connection BEFORE restarting anything "
            "— a reboot destroys the evidence and rarely removes the cause. "
            "Isolate the machine from the network rather than only blocking "
            "the one address; an implant that loses a C2 address simply "
            "uses the next one."
        ),
    ),

    # --- suppression: explain an alert away rather than raise one ---------
    CorrelationRule(
        id="dns_failure_explained_by_captive_portal",
        requires=("captive_portal", "dns_resolution_failure"),
        severity="warning",
        confidence="likely",
        story=(
            "DNS is failing because a captive portal is intercepting this "
            "connection, not because DNS is broken. This is one problem "
            "with two symptoms — signing in to the portal should resolve "
            "both."
        ),
        suggested_action=(
            "Complete the portal sign-in, then re-check. Do not change DNS "
            "settings on the basis of this failure."
        ),
        suppresses=("dns_resolution_failure",),
    ),

    CorrelationRule(
        id="everything_downstream_of_dead_link",
        requires=("link_down", "dns_resolution_failure"),
        severity="critical",
        confidence="certain",
        story=(
            "No network interface is up, which fully explains the DNS "
            "failure and anything else above it. There is one fault here, "
            "not several — fix the link and re-test before investigating "
            "anything downstream."
        ),
        suggested_action=(
            "Restore the physical/Wi-Fi link first; treat every other "
            "network finding as unconfirmed until it comes back."
        ),
        suppresses=("dns_resolution_failure",),
    ),

    # --- cross-engine agreement: two tools, one fault ---------------------
    CorrelationRule(
        id="dns_failure_confirmed_by_both_engines",
        requires=("dns_resolution_failing", "dns_resolution_failure"),
        severity="critical",
        confidence="certain",
        story=(
            "Host diagnostics and network diagnostics independently found "
            "DNS resolution failing. Two tools agreeing is one fault "
            "confirmed twice, not two faults. (Note the near-identical "
            "ids: Diagnostic Companion reports `dns_resolution_failing`, "
            "netdiag `dns_resolution_failure` — one letter apart, which "
            "is why rule ids are validated against both engines' "
            "knowledge bases by test.)"
        ),
        suggested_action=(
            "Check the configured resolvers; the agreement between engines "
            "makes a transient measurement error unlikely."
        ),
    ),
)


def rules_for(finding_ids) -> List[CorrelationRule]:
    """Rules whose required findings are all present."""
    present = set(finding_ids)
    return [r for r in RULES if present.issuperset(r.requires)]
