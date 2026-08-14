"""Skill registry + auto-discovery — the native shell's verb table (A3 Phase 4).

A lean port of the fork's `skill_registry`, keeping the parts the ops role
uses and dropping the parts it does not. Gone: the hardcoded the predecessor project verbs
(joke / story / weather / whereami / language) and the macro fallback baked
into `resolve`; those were assistant features, not routing. Kept: the
name+alias table, verb-first resolution (`census passive` → verb `census`,
args `passive`), and honest "no match" so the caller can route an unmatched
question to the grounded answer path instead.

Discovery uses the platform's own `register(registry)` convention (each
`skills/<verb>.py` exposes one), loaded by a unique module name so it never
touches the two-`skills`-package ambiguity the fork fought. `disabled_modules`
carries the A2 lean-build gate forward.
"""

import importlib.util
import os
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

SkillFn = Callable[[str, Any], Any]      # (args, speaker) -> result

_PUNCT = re.compile(r"[^a-z0-9\s]")
_SPACE = re.compile(r"\s+")


def _norm(value: str) -> str:
    cleaned = _PUNCT.sub(" ", (value or "").lower())
    return _SPACE.sub(" ", cleaned).strip()


class SkillRegistry:
    """Maps verb names and aliases to skill functions."""

    def __init__(self) -> None:
        self.skills: Dict[str, SkillFn] = {}
        self.aliases: Dict[str, str] = {}
        #: (module stem, reason) for every skill that failed to load.
        #: A verb that vanishes silently is a verb the operator believes
        #: they still have — see `auto_discover`.
        self.failures: List[Tuple[str, str]] = []

    def register(self, name: str, fn: SkillFn,
                 aliases: Optional[List[str]] = None) -> None:
        norm = name.strip().lower()
        self.skills[norm] = fn
        for alias in (aliases or []):
            self.aliases[alias.strip().lower()] = norm

    def resolve(self, raw: str) -> Tuple[Optional[str], str]:
        """(verb, args) for a command, or (None, text) when nothing matches.

        Order: the whole string as an exact verb/alias, then verb-first (the
        first word names the verb, the rest are its args), then a
        punctuation-normalised whole-string alias. No fuzzy guessing — an
        ops console prefers "no match, treat it as a question" over a wrong
        verb.
        """
        text = (raw or "").strip()
        low = text.lower()
        if low in self.aliases:
            return self.aliases[low], ""
        if low in self.skills:
            return low, ""

        head, _, rest = text.partition(" ")
        head = head.strip().lower()
        if head in self.aliases:
            return self.aliases[head], rest.strip()
        if head in self.skills:
            return head, rest.strip()

        # A multi-word alias as a prefix carries trailing args:
        # "lan census now" → verb census, args "now". Longest alias wins.
        for alias in sorted(self.aliases, key=len, reverse=True):
            if low.startswith(alias + " "):
                return self.aliases[alias], text[len(alias):].strip()

        norm = _norm(text)
        if norm in self.aliases:
            return self.aliases[norm], ""
        return None, text

    def names(self) -> List[str]:
        return sorted(self.skills)

    def catalog(self) -> str:
        """A compact `verb: alias, alias` listing, aliases grouped by verb."""
        by_verb: Dict[str, list] = {}
        for alias, target in self.aliases.items():
            by_verb.setdefault(target, []).append(alias)
        lines = []
        for name in sorted(self.skills):
            sample = by_verb.get(name, [])[:5]
            lines.append(f"- {name}: {', '.join(sample)}" if sample else f"- {name}")
        return "\n".join(lines)


def auto_discover(registry: SkillRegistry, skills_dir: str,
                  disabled_modules=None) -> int:
    """Import each `skills/<verb>.py` and call its `register(registry)`.

    Returns the number of verbs registered. `disabled_modules` (module stems)
    are skipped — the A2 lean-build gate. Each module is loaded under a unique
    name (`_ops_skill_<verb>`) so discovery never binds the `skills` package,
    the source of the fork's collision.
    """
    if not os.path.isdir(skills_dir):
        return 0
    disabled = set(disabled_modules or ())
    before = len(registry.skills)
    for filename in sorted(os.listdir(skills_dir)):
        if not filename.endswith(".py") or filename.startswith("_"):
            continue
        stem = filename[:-3]
        if stem in disabled:
            continue
        path = os.path.join(skills_dir, filename)
        try:
            spec = importlib.util.spec_from_file_location(f"_ops_skill_{stem}", path)
            if spec is None or spec.loader is None:
                registry.failures.append((stem, "no import spec"))
                continue
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        except Exception as exc:  # noqa: BLE001 - one broken skill must not sink the rest
            registry.failures.append((stem, f"{type(exc).__name__}: {exc}"))
            continue
        register_fn = getattr(module, "register", None)
        if not callable(register_fn):
            registry.failures.append((stem, "no register(registry) function"))
            continue
        try:
            register_fn(registry)
        except Exception as exc:  # noqa: BLE001
            registry.failures.append((stem, f"{type(exc).__name__}: {exc}"))
    return len(registry.skills) - before


def failure_report(registry) -> str:
    """One block naming every verb that failed to load, or "" if all did.

    Discovery deliberately survives one broken skill — but it used to do so
    in complete silence, and a silently missing verb is worse than a crash.
    The operator reads a verb list that looks complete, does not find the
    verb they wanted, and concludes they misremembered its name. That is
    exactly how `admin` went missing during its own development: a bad
    keyword argument, swallowed, no trace anywhere.

    Nothing here is fatal. It is only said out loud.
    """
    failures = getattr(registry, "failures", None)
    if not failures:
        return ""
    lines = [f"  {len(failures)} skill(s) FAILED TO LOAD — these verbs are missing:"]
    for stem, reason in failures:
        lines.append(f"    {stem}: {reason}")
    lines.append("  Everything else loaded. This is not an all-clear.")
    return "\n".join(lines)
