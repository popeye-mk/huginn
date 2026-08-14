# Architecture

The structure decided once, up front, so it doesn't get rebuilt later. Every rule here exists because breaking it produces a specific, predictable mess.

---

## The five layers

Dependencies point **downward only**. A layer may import from layers below it, never above or sideways across domains.

```
┌──────────────────────────────────────────────────────────┐
│  skills/      Anora skill registrations. Thin. No logic. │  ← user-facing verbs
├──────────────────────────────────────────────────────────┤
│  agents/      AgentContract implementations. Routing.    │  ← AI layer
├──────────────────────────────────────────────────────────┤
│  domains/     Business logic. One folder per subdomain.  │  ← the actual work
├──────────────────────────────────────────────────────────┤
│  engines/     Wrappers over external tools. I/O lives    │  ← the only subprocess calls
│               here and nowhere else.                     │
├──────────────────────────────────────────────────────────┤
│  contracts/   Pure data types. No logic, no I/O, no      │  ← the shared language
│               imports from anything above.               │
└──────────────────────────────────────────────────────────┘
        platform_support/  — OS detection, path resolution (importable by any layer)
```

**Why this direction:** the thing most likely to change is the tools (a new backup engine, a replacement for netdiag). The thing least likely to change is what a "finding" is. Pointing dependencies at the stable core means swapping an engine touches one file, not thirty.

---

## Layer rules

### `contracts/` — the shared language
- Pure dataclasses and enums. **No I/O. No subprocess. No imports from other layers.**
- If a contract needs to *do* something beyond validating itself, that logic belongs in a domain.
- Everything above speaks these types. Engines never leak their native output shape upward.

### `engines/` — the only place that touches the outside world
- One module per external tool. `diagnostic_companion.py`, `netdiag.py`, `restic.py`.
- **Every `subprocess` call in the codebase lives in this layer.** If you need to shell out from a domain, you need an engine instead.
- Engines return `EngineOutput` (raw payload + metadata). They **do not** produce `Finding` objects — mapping is the domain's job, because mapping is a decision and engines should stay dumb.
- Cross-platform binary selection happens here, via `platform_support/`.

### `domains/` — the business logic
- One folder per subdomain: `diagnostics/`, `network/`, `devices/`, `backup/`.
- **Domains never import each other.** If `devices` needs diagnostics data, it receives it as a `Finding` argument — it does not reach into `domains/diagnostics/`. Cross-domain coordination is the agent layer's job.
- Standard shape inside a domain:
  - `service.py` — the public entry point. The only thing outside layers import.
  - `mapping.py` — engine output → contracts.
  - `repository.py` — persistence, where relevant. **The only place that touches the database.**
- No `utils.py`. It is where god-files start: a name that means "anything" collects everything. Name the module for what it does.

### `agents/` — the AI layer
- Implements Anora's `AgentContract` (`can_handle` / `plan` / `execute` / `explain`).
- **Agents never call each other** — that's Anora's existing rule and it holds here. The coordinator decides who runs.
- Agents may call multiple domain services; that is precisely their job.
- Agents contain *routing and explanation*, not business logic. If an agent grows a calculation, it belongs in a domain.

### `skills/` — user-facing verbs
- Registration + argument parsing + formatting. Nothing else.
- A skill body should read as: parse args → call one service or agent → format result.
- **Hard rule: a skill that contains an `if` about business meaning is too fat.** Push it down.

---

## Domain map

| Domain | Subdomain | Owns | Engine |
|---|---|---|---|
| `ops` | `diagnostics` | Host health findings | Diagnostic Companion |
| `ops` | `network` | Network-layer findings, blame partition | netdiag |
| `ops` | `devices` | Fleet inventory, correlation, health scores | (fleet.py, via diagnostics output) |
| `ops` | `backup` | Restore verification, sandbox lifecycle | Restic + KVM/Hyper-V |

Subdomains are siblings, not a hierarchy. `devices` aggregates *data* from the others but does not depend on their *code*.

---

## The no-god-file rules

Enforced automatically by `tools/test_architecture.py`, not by discipline.

| Rule | Limit | Rationale |
|---|---|---|
| Module length | **300 lines** (soft), **400** (hard fail) | Past ~300 lines a module almost always has two responsibilities |
| Function length | **50 lines** | Longer usually means missing intermediate concepts |
| No `utils.py` / `helpers.py` / `misc.py` | — | Catch-all names collect unrelated code by design |
| One class per module for services/agents | — | Two services in a file means the file has two reasons to change |
| No upward imports | — | `contracts` importing `domains` inverts the whole model |
| No cross-domain imports | — | `domains/devices/` importing `domains/backup/` couples what should be independent |

**On the 400-line hard limit:** Anora's own largest modules (`memory_semantic.py` at 902, `knowledge/query.py` at 888) are exactly the files that would be hardest to change safely today. The limit exists so this codebase doesn't acquire its own versions of those.

---

## Dead code policy

- **No stub files.** An empty module "for later" is dead code with a promise attached. Create the file when the code exists.
- **No commented-out blocks.** Git remembers; the file shouldn't.
- **No unreferenced modules.** The architecture test fails on any module in `domains/` or `engines/` that nothing imports — this catches abandoned work before it becomes archaeology.
- Deleting is a normal, expected activity. If a module stops earning its place, it goes.

---

## Cross-platform rule

`platform_support/` is the only layer allowed to branch on operating system.

```python
# Wrong — scattered OS knowledge
if platform.system() == "Windows":
    binary = "netdiag_windows_amd64.exe"

# Right — one place knows
from platform_support import resolve_binary
binary = resolve_binary("netdiag")
```

Everywhere else treats the OS as already resolved. This is what keeps "works on both" from decaying into "works on the one I tested."

---

## Where this differs from Anora's existing layout

Anora `05-04` is already well-structured — `anora.py` is 497 lines (down from 3,689), and `agents/base.py` defines a proper contract. This design deliberately conforms to it rather than competing:

- Ops agents implement Anora's `AgentContract` unchanged.
- Ops skills register through Anora's existing `SkillRegistry`.
- The ops layers slot in as one coherent domain rather than a second framework.

The one place this is stricter: Anora has no enforced module-size limit, and its largest files show it. The ops platform enforces one from the start.

---

## Adding something new — the checklist

1. New external tool → `engines/<tool>.py`, returns `EngineOutput`
2. New concept → `contracts/<concept>.py`, pure data
3. New logic → `domains/<subdomain>/service.py`
4. New persistence → `domains/<subdomain>/repository.py`
5. New user verb → `skills/<verb>.py`, thin
6. Needs to span subdomains → that's an agent, not a domain

If a change doesn't fit these six, the architecture is wrong and should be discussed — not worked around.
