"""Intent routing table — pure data.

Separated from `ops_agent` when the route list outgrew the 50-line
function limit. That limit was right: a table of keywords is data, and
keeping it inside a method mixed "what phrases mean what" with "how the
agent wires itself up". Adding a verb now means adding a row here, not
editing a function.

**Order matters.** The first match wins, so narrower intents come first.
"history of network problems" must reach `history` rather than being
swallowed by `netcheck`'s "network" keyword, and "network security"
must reach `security` rather than `netcheck`.

Keywords are EN/NL/FR throughout, matching the predecessor project's trilingual
convention — the target user is a Belgian solo admin, and a tool that
only understands English commands is a tool they translate for.
"""

from dataclasses import dataclass
from typing import Tuple


@dataclass(frozen=True)
class RouteSpec:
    """What an intent is called and how it is recognised."""

    intent: str
    keywords: Tuple[str, ...]
    description: str


ROUTE_SPECS: Tuple[RouteSpec, ...] = (
    RouteSpec(
        intent="history",
        keywords=(
            "history", "past", "before", "previously", "recurring",
            "last week", "seen before", "happened", "recall",
            "geschiedenis", "eerder", "eerder gezien",          # NL
            "historique", "auparavant",                         # FR
        ),
        description="Recall past findings for this machine",
    ),
    RouteSpec(
        intent="threat",
        keywords=(
            "threat", "threats", "c2", "malware", "compromised",
            "who is my machine talking to", "outbound", "connections",
            "indicators", "ioc", "blocklist",
            "dreiging", "verbindingen",                         # NL
            "menace", "connexions",                             # FR
        ),
        description="Check outbound connections against threat feeds",
    ),
    RouteSpec(
        intent="backup",
        keywords=(
            "backup", "restore", "recovery", "restic", "snapshot",
            "can we restore", "backup test", "verify backup",
            "back-up", "herstel", "herstellen",                 # NL
            "sauvegarde", "restauration",                       # FR
        ),
        description="Verify that a backup can actually be restored",
    ),
    RouteSpec(
        intent="devices",
        keywords=(
            "devices", "fleet", "machines", "all machines", "estate",
            "apparaten", "toestellen",                          # NL
            "appareils", "parc",                                # FR
        ),
        description="Every machine this platform knows about",
    ),
    RouteSpec(
        intent="triage",
        keywords=(
            "triage", "correlate", "full check", "everything",
            "what's going on", "whats going on", "overview",
            "volledige controle",                               # NL
            "analyse complète", "analyse complete",             # FR
        ),
        description="Run every engine and report shared root causes",
    ),
    RouteSpec(
        intent="security",
        keywords=(
            "security", "exposure", "hygiene", "posture",
            "beveiliging",                                      # NL
            "sécurité", "securite",                             # FR
        ),
        description="Report network security exposure on this machine",
    ),
    RouteSpec(
        intent="netcheck",
        keywords=(
            "network", "internet", "connection", "connectivity", "wifi",
            "netwerk",                                          # NL
            "réseau", "reseau",                                 # FR
        ),
        description="Check the network and name what is at fault",
    ),
    RouteSpec(
        intent="diagnose",
        keywords=(
            "diagnose", "health", "healthcheck", "what's wrong",
            "check machine",
            "diagnostiek",                                      # NL
            "diagnostic",                                       # FR
        ),
        description="Run host health diagnostics on this machine",
    ),
    RouteSpec(
        intent="census",
        keywords=(
            "census", "network devices", "who is on the network",
            "lan census",
            "netwerkapparaten",                                 # NL
            "appareils réseau",                                 # FR
        ),
        description="List LAN devices and flag what changed (Network Guard G1)",
    ),
    RouteSpec(
        intent="label",
        keywords=(
            "label", "tag", "rename", "label device", "name device",
            "tag device",
            "noem apparaat",                                    # NL
            "nommer appareil",                                  # FR
        ),
        description="Give a LAN device a friendly name by hand "
                    "(Network Guard G1f)",
    ),
    RouteSpec(
        intent="guard",
        keywords=(
            "guard", "anomaly", "arp spoof", "arp spoofing", "rogue dhcp",
            "network attack", "mitm", "poisoning",
            "netwerkaanval",                                    # NL
            "attaque réseau",                                   # FR
        ),
        description="Watch the LAN for ARP spoofing and rogue DHCP "
                    "(Network Guard G3)",
    ),
    RouteSpec(
        intent="namewatch",
        keywords=(
            "namewatch", "llmnr", "mdns", "responder", "resolver check",
            "name resolution attack",
            "naamvergiftiging",                                 # NL
            "empoisonnement de noms",                           # FR
        ),
        description="Probe for an LLMNR/mDNS name-resolution poisoner "
                    "(Network Guard G8)",
    ),
    RouteSpec(
        intent="expose",
        keywords=(
            "expose", "exposure", "open ports", "port scan", "dangerous ports",
            "exposure scan",
            "blootstelling",                                    # NL
            "exposition",                                       # FR
        ),
        description="Scan LAN devices for dangerous open ports "
                    "(Network Guard G2)",
    ),
    RouteSpec(
        intent="ack",
        keywords=(
            "ack", "acknowledge", "accept exposure", "mute finding",
            "known good",
        ),
        description="Accept an exposure as known-good so it stops flagging "
                    "(Network Guard G2b)",
    ),
    RouteSpec(
        intent="patrol",
        keywords=(
            "patrol", "guard patrol", "network patrol", "sweep and watch",
            "netwerkpatrouille",                                # NL
            "patrouille réseau",                                # FR
        ),
        description="Run one unattended guard pass — census + anomaly + "
                    "exposure, alert on change (Network Guard G4)",
    ),
    RouteSpec(
        intent="timeline",
        keywords=(
            "timeline", "guard timeline", "lan history", "what changed",
            "changes", "network timeline", "what changed this week",
            "tijdlijn",                                         # NL
            "chronologie",                                      # FR
        ),
        description="What changed on the LAN over the last N days "
                    "(Network Guard G7)",
    ),
    RouteSpec(
        intent="dashboard",
        keywords=(
            "dashboard", "guard dashboard", "network dashboard",
            "pane of glass",
            "overzicht",                                        # NL
            "tableau de bord",                                  # FR
        ),
        description="Render the guard's current state as a read-only HTML "
                    "dashboard (Network Guard G5)",
    ),
    RouteSpec(
        intent="digest",
        keywords=(
            "digest", "weekly digest", "guard digest", "weekly summary",
            "briefing",
            "weekoverzicht",                                    # NL
            "résumé hebdomadaire",                              # FR
        ),
        description="Weekly guard briefing: devices, what changed, persistent "
                    "attacks (Network Guard G12)",
    ),
    RouteSpec(
        intent="harden",
        keywords=(
            "harden", "posture", "host posture", "hardening", "attack surface",
            "preconditions", "what would work",
            "verharden",                                        # NL
            "durcissement",                                     # FR
        ),
        description="Standing conditions that would let a LAN attack succeed "
                    "(Network Guard H1)",
    ),
    RouteSpec(
        intent="capture",
        keywords=(
            "capture", "incident", "snapshot", "freeze", "evidence",
            "forensics",
            "momentopname",                                     # NL
            "instantané",                                       # FR
        ),
        description="Freeze the volatile evidence into a timestamped file "
                    "(Network Guard H2)",
    ),
    RouteSpec(
        intent="mitigate",
        keywords=(
            "mitigate", "mitigation", "recommend fix", "how to fix",
            "harden", "block advice",
            "beveiligingsadvies",                               # NL
            "conseil de sécurité",                              # FR
        ),
        description="Recommend copy-pasteable fixes for confirmed findings — "
                    "operator runs them (Network Guard G6, advice-only)",
    ),
)
