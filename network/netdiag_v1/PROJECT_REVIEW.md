# netdiag — project review at the stable base (0.9.10-v1.5)

Written after the first full field campaign: two operating systems, three
machines, a live AD domain, and twenty bugs found by running the thing rather
than by reading it.

---

## Where the project actually is

| | |
|---|---|
| Code | ~10,350 lines Go, zero external dependencies |
| Tests | ~1,480 lines, 9 packages green, 22 harness scenarios |
| Knowledge base | 55 rules (L1:7 L2:6 L3:13 L4:4 L7:25) |
| Facts classified for redaction | 74 |
| Platforms | Linux + Windows, one static binary each |
| Field-verified | Zorin laptop, Win 11 client, Windows Server DC |

**Verdict: the base is real.** Not "it compiles" real — it found genuine
faults on machines we did not plant them on (dead IPv6 dual-stack, MTU 1380,
LLMNR exposure, 20 Wi-Fi disconnects), and it refused to invent another when a
slow test server invited it to.

**Two of the six originally claimed here were false positives**, both found by
using the tool rather than testing it: the "hosts-file overrides" were stock
distro boilerplate (bug #24) and the "126 link flaps" were an unplugged
ethernet port on a laptop working over Wi-Fi (bug #31). Both were cited as
evidence the tool worked, for weeks, in this document. That is worth leaving
visible: a finding is not a fault until someone reads its evidence, and the
person most likely to skip that step is the one who wrote the rule.

---

## What is genuinely good, and worth protecting

**1. The honesty discipline is the whole product.**
"Absence is never health" is not a slogan here — it is enforced by
`redact_test.go` failing the build on unclassified facts, by every collector
reporting skip/timeout with a reason, and by the verdict logic refusing to
grade an unloaded link. Nineteen of twenty field bugs were the tool being
*confidently wrong*, and each fix made a claim narrower rather than louder.
That is the asset. Everything else is replaceable.

**2. The blame partition is the differentiator.**
"It is not you, it is past your gateway" as a HEADLINE, before any detail,
is what turns a wall of facts into a decision. No competing tool leads with it.

**3. The `why` verbs match how tickets actually arrive.**
Users do not say "check my SRV records", they say "I can't log in". The
mapping from symptom → layer walk → first break → named fix is the hour-not-
a-day claim, and `why cant-login` is the strongest example: DNS fitness, SRV,
ports, clock and machine trust in one command.

**4. Field bugs became regression tests.**
Every one of the twenty has a test with a comment naming the run that found
it. That is why the tool will not quietly regress into its old lies.

---

## The honest weaknesses

**1. Test coverage is lopsided where risk is highest.**

```
collectors   5.2%   ← 4,580 lines, the biggest and least tested package
triage      30.3%   ← 1,185 lines, contains every walk verdict
loadtest    29.6%
cmd/netdiag  0.0%   ← 1,141 lines, all the verb wiring and output
report       0.0%
```

The collectors are hard to unit-test (they read real /proc, real registry),
but that is exactly where the platform-specific lies came from: the DHCP
struct offsets, the nltest cache, the localized output. The pattern that
worked — pure parsing functions fed captured real output (`nltest_test.go`,
the IEEE parser tests) — should be applied to the rest: extract parsing from
I/O, test against captured fixtures.

**2. `cmd/netdiag` has no tests and 1,141 lines.**
Verb dispatch, flag handling and output formatting are untested. The `-url`
ignoring bug lived exactly here.

**3. Three files are too long to reason about.**
`collectors_windows.go` (1,172), `walk.go` (670), `main.go` (535). Each is a
grab-bag. Splitting by concern would make the next contributor's life
possible.

**4. The KB is L7-heavy and thin at L2.**
25 of 51 rules are L7, only 2 at L2. Real switching problems (VLAN mismatch,
duplex, port security, STP) are under-represented — and those are bread and
butter for a support engineer on a corporate LAN.

**5. `netem` tier never runs in this environment.**
5 rules are tagged netem and the harness skips them honestly. They have never
been executed anywhere. That is a known, stated gap — but it means loss/jitter
rules are fixture-tested only.

**6. Windows depends on external binaries.**
`netsh`, `wevtutil`, `dsregcmd`, `nltest`, `sc`, `powershell`, `reg`. Each is
a place where a locale, a Windows edition, or a policy can change the answer.
The French-locale and cached-session bugs both came from here. Judged by exit
code or numeric status now, but the surface remains.

---

## What to do next, in the order I would do it

### Tier 1 — makes the tool trustworthy at scale (do these first)

**1. Extract and test the parsers.** ✅ **DONE (0.9.11)** — see the log at the
bottom of this file. Collectors 5.2% → 13.4%, and it immediately found a real
shipped bug (French Windows `sc query`). Not finished: the event-log miners,
`netsh advfirewall`, `certutil` and the WEXT ioctl decoding are still
untested. Next pass should take collectors past 25%.

**2. Test the verb layer.** ✅ **DONE (0.9.12)** — see the log at the bottom.
`report` 0% → 90.5%, `cmd/netdiag` 0% → 7.1%, and the two bugs this item
existed to catch (`-url` ignored, "all 3 segments healthy" above a critical
finding) now both have regression tests. Not finished: verb dispatch in
`main.go` and the scan/why paths still need a collector seam to be testable
without a network — that is what item 3 gives us.

**3. A `netdiag selftest` verb.** ✅ **DONE (0.9.13)** — see the log at the
bottom. 13 checks, no network, exit-code contract, and it found bug #22 (the
whole AD evidence set vanishing from `--redact` reports) on its first run.
**Tier 1 is complete.**

### Tier 2 — makes it better at the daily job

**4. L2 rules.** ✅ **DONE (0.9.14)** — L2 went 2 → 6, all firing on facts
already collected. Still open and honestly out of reach without new
collection: VLAN-from-DHCP-scope mismatch, STP topology-change storms, and
switch-port counters via LLDP all need data this tool does not gather yet.

**5. `netdiag why slow` deserves the bufferbloat integration.** ✅ **DONE
(0.9.14)** — as an offer, not an auto-run, and only when the passive walk
found nothing. See the log for why that boundary matters.

**6. Ticket-ready export.** ✅ **DONE (0.9.15)** — `netdiag ticket [symptom]
[target]`, plain text, with the two sections no other renderer has: RULED OUT
and NOT CHECKED.

**7. Historical baselines.** ✅ **DONE (0.9.16)** — last 10 kept per location;
`-diff -against 2 | 2026-07-14 | 7d`, and `baseline -list`. **Tier 2 is
complete.**

### Tier 3 — the honest maybes

**8. Signed Windows binary.** Needs a real certificate in your name. Until
then SmartScreen will keep frightening users.

**9. A real GUI.** Deferred deliberately. The menu covers most of the value;
a windowed app costs the single-static-binary property. Decide it as a
product question, not a technical one.

**10. Upload/latency-under-upload.** Only download bufferbloat is measured.
Upload saturation is the one that actually breaks video calls, and it is
missing.

---

## The thing to guard as it grows

Every feature added from here will be tempted to say more than it knows.
The speed test tried to blame an ISP from a throttled server. The secure
channel reported a cached success as verified. The device list called a
broadcast address a phone.

The rule that has served this project best, and should be the review question
for every future change:

> **Does this claim survive being wrong?**
> If the measurement failed, does the output say so — or does it show green?

Everything else is negotiable. That is not.

---

## Work log

### 0.9.11 — Tier 1 item 1: parsers extracted and tested

**What was done**

`internal/collectors/parse.go` — a new file with no build tag and no I/O,
holding the interpretation that used to be tangled up with the syscalls:

| Parser | Was buried in | Why it matters |
|---|---|---|
| `DefaultGatewayFromRoute` | collectors_linux.go | little-endian hex, easy to get backwards |
| `HexPort` | sockets_linux.go | /proc/net/tcp address halves |
| `ResolvConfServers` | dnsextra_linux.go | a commented resolver is not a resolver |
| `ProcNetWireless` | wifi_linux.go | values carry trailing dots ("70.", "-37.") |
| `SCServiceRunning` | collectors_windows.go | **localised — see the bug below** |
| `NetshValue` | collectors_windows.go | netsh's inconsistent indentation |
| `DsregcmdState` | collectors_windows.go | domain/Azure join + realm |
| `RegValueHex` | collectors_windows.go | REG_DWORD extraction |
| `PnPPowerSaving` | collectors_windows.go | inverted-sense bit test (0x18) |
| `PrintQueueCounts` | collectors_windows.go | absent ≠ empty queue |
| `DHCPFromRegistry` | collectors_windows.go | replaced the struct walk that reported "255" |

`parse_test.go` — fixtures captured from the real machines in this campaign
(Zorin laptop route table and /proc/net/wireless, Win 11 dsregcmd and DHCP
registry, DC service output) plus deliberate negative cases: garbage input,
absent keys, commented-out resolvers, headers-only files. Every parser is
asserted to report **not measured** rather than a plausible-looking default.

The collectors now call these instead of carrying their own copies, so the
tests cover shipped behaviour rather than a parallel implementation.

**Bug #21, found by writing the test rather than by running the tool**

`sc query` prints `STATE : 4 RUNNING` in English — and `ÉTAT` in French,
`STATUS` in German. The shipped parser searched for the word "STATE", so on
any non-English Windows it found nothing and reported `spooler_running =
false`. That is a **critical finding invented on a healthy machine**: `why
cant-print` would have told a French user their spooler was stopped and sent
them to restart a service that was running perfectly.

Fixed by ignoring words entirely: scan every `key : value` line and take the
one whose value is a service-state number (1–7). TYPE values are 16/32/272 and
cannot collide. No state line at all now means *not measured*, never
*stopped*.

This is the third localisation bug in the same family (French `nltest`,
localised `sc query`, and the cached secure channel that spoke English
perfectly while lying). The lesson is now enforced by test rather than by
memory: **on Windows, judge by numbers; words are decoration.**

**Numbers**

- collectors coverage: 5.2% → **13.4%**
- new tests: 11 functions, ~250 lines, all runnable on any OS
- Windows string parsing: was **uncompilable** off Windows, now fully testable
- all 9 packages green, both build targets vet-clean, harness unaffected

**Not done, and honest about it**

The percentage is still low because the package is 4,580 lines and most of it
is syscall plumbing (IP Helper struct walks, WEXT ioctls) that a unit test
cannot reach. The remaining *parsing* surfaces worth extracting next:
`wevtutil` event counting, `netsh advfirewall` state, `certutil` CA scanning,
journalctl/syslog event mining, and the WEXT byte decoding.

### 0.9.12 — Tier 1 item 2: the verb and report layer under test

**What was done**

Three new test files, all runnable on any OS, none of them touching a network.

`internal/report/report_test.go` — the report is the product, and it was 0%
covered. Eight property tests, asserted across all four renderers (terminal,
markdown, HTML, `--for-user`):

| Property | Why it is the one that matters |
|---|---|
| an unchecked layer never renders as clean | the whole "absence is never health" promise, in one assertion |
| a skip keeps its REASON | "skipped" without why is not honesty, it is a shrug |
| every finding carries its next step | a finding without a remedy is trivia |
| the read-only promise appears in every format | it is why the tool is safe on someone else's machine |
| the blame headline precedes the layer detail | the ordering *is* the differentiator |
| `--for-user` contains no rule ids or fact keys | jargon leaking here defeats the mode |
| HTML escapes hostile hostnames and verdicts | the report gets mailed around; it must not be an injection vector |
| errored and timed-out collectors are listed | an errored collector is as unmeasured as a skipped one |

`cmd/netdiag/pipeline_test.go` — end-to-end through the REAL assembly:
embedded KB, real blame logic, real renderer, driven by synthetic facts. This
is the level at which the worst field bugs lived — every component correct in
isolation, the assembled sentence still wrong. It pins bug #7 (a critical
finding can never sit under an all-clear headline), and its mirror image (a
genuinely quiet machine still gets the all-clear, qualified, and the tool does
not invent a fault to look useful). Also: a dead gateway leaves the WAN
*unknown* rather than blamed, empty facts blame nobody, and the DC segment
appears only when a domain was named.

`cmd/netdiag/cmd_test.go` — the verb layer, which shipped the `-url` bug at
0% coverage. Menu catalogue completeness (every entry has a runner, a label in
the user's words rather than ours, a hint, and a way back out), the
`exitForGrade` contract that scripts gate on, `wrap` losing no word from a
verdict, and `f64` accepting both the int a collector produces and the float64
a JSON baseline round-trips into.

**Two refactors, both to create a testable seam rather than to be tidy**

- `menuItems()` split out of `menuCmd()`, so the catalogue can be asserted
  without a terminal.
- `speedOptionsFrom(args)` split out of `speedCmd()`, so what the flags
  *decide* can be checked without moving a byte. This is exactly where the
  `-url` bug lived: the flag parsed correctly and the value never won the
  server race. There is now a test asserting that an explicit `-url` also
  clears the fallback list — and its opposite, that a default run keeps at
  least two fallbacks, because the Cloudflare 403 proved a single hard-coded
  server kills the feature outright.

**Numbers**

- `internal/report`: 0% → **90.5%**
- `cmd/netdiag`: 0% → **7.1%**
- 21 new test functions, ~430 lines
- all 10 test packages green, both build targets vet-clean

**Not done, and honest about it**

`cmd/netdiag` is 7.1%, not 70%. The remaining bulk is verb dispatch and the
scan/why paths, and those cannot be tested until the collectors can be
substituted — they call the network on the line they are invoked. The next
item (`netdiag selftest`) needs that same seam: a way to drive the whole tool
from a fact fixture instead of a machine. Doing item 3 properly therefore
finishes item 2 as a side effect, which is why it is next rather than the L2
rules.

### 0.9.13 — Tier 1 item 3: `netdiag selftest`

**What it is**

    netdiag selftest            # 13 checks, no network, ~10 ms
    netdiag selftest -quiet     # one line, for scripts and imaging pipelines
    netdiag selftest -kb my.json  # validate a hand-edited knowledge base

Exit 0 = the reasoning is intact. Exit 1 = do not believe this binary's
verdicts.

**Why a verb and not just another unit test**

Unit tests prove the build was good on the machine that compiled it. They say
nothing about the binary in the customer's hand after a USB copy, an antivirus
quarantine-and-restore, or a field tech hand-editing `kb.json` at 2am — and
that last case no unit test can ever see, because the KB did not exist when
the tests ran. `selftest` pushes fixed facts through the **real** rules engine,
the **real** blame logic and the **real** renderer, and checks the sentences
that come out.

**The 13 checks**

Three are KB integrity: it loads and is non-empty (a truncated KB would
otherwise report every machine as healthy); every rule has an id, a valid
layer and severity, finding text, a next step, plain-language text, and a
match clause that can actually fire; and no rule reads a fact with no
redaction classification. One validates the symptom walks — a `why` verb with
an empty walk reports a clean run on a broken machine.

The other nine are the frozen list of lies this tool has told: a healthy
machine is not given a fault, and the all-clear stays qualified; nothing
measured blames nobody; a dead gateway leaves the WAN unknown rather than
blamed; a down link is not graded; bug #7 (a critical finding cannot sit under
an all-clear headline); bug #10 (an *unverifiable* secure channel is not
reported as broken trust) **and its mirror** — a channel that is verifiably
broken must still fire, because a fix that mutes the real fault is not a fix;
and the DC segment appears when a domain was probed and not otherwise.

**Bug #22, found by the selftest on its first run**

The redaction check failed against the shipped KB. Ten facts written by the
triage *probe* layer — `dns_public_resolver_only`, `ad_srv_resolved`,
`ad_dc_clock_offset_ms` and the rest of the AD set — had no entry in
`RedactionPolicy`. `redact_test.go` never caught it because it validates facts
emitted by *collectors*, and these are written by the probe layer instead.

Nothing leaked: unclassified defaults to `Drop`. The damage ran the other way.
Every piece of evidence behind `why cant-login`'s critical findings silently
vanished from `--redact` output — which is precisely the report a support
engineer emails to a colleague or attaches to a ticket. The reader got the
accusation with the evidence stripped out, and no indication anything had been
removed. **A finding whose evidence disappears is a claim the reader cannot
check**, which is the same failure this project exists to avoid, arriving
through a side door.

Eight are now `Keep` (booleans and counts, no site identity). `ad_dcs` and
`ad_srv_by_resolver` are `Drop` — they carry internal hostnames and addresses,
same treatment as `ad_realm`.

**One refactor, to stop this class recurring**

`interpret.FactKey(matchKey)` is now exported and used by both the engine and
the audit. Rule keys carry comparators (`gateway_loss_pct_above` reads the
fact `gateway_loss_pct`), and my first version of the check did not strip
them, so it reported 17 false positives. Two copies of that mapping would have
drifted silently; there is now one.

**Also proved: the suite can fail**

`TestTheSuiteCanActuallyFail` runs a deliberately impossible scenario and
asserts it reports FAIL. A selftest that always prints PASS is worse than no
selftest, because it manufactures confidence. Every scenario must also state
what it guards and assert at least one thing — a scenario that asserts nothing
passes trivially and inflates the count.

**Numbers**

- `internal/selftest`: **66.9%**, 5 test functions
- 13 runtime checks, 51 rules and 8 symptom walks validated
- all 11 test packages green, both build targets vet-clean
- runtime ~10 ms, no network, no system state read, nothing changed

**Tier 1 is now complete.** Parsers extracted and tested (0.9.11), the report
and verb layer under test (0.9.12), and the build able to prove itself in the
field (0.9.13). Three real bugs came out of the three items — #21 French
`sc query`, the `-url` regression pinned, and #22 vanishing evidence — none of
which a passing build would have revealed on its own.

Next is Tier 2 item 4 (L2 rules), where the KB is thinnest: 2 rules out of 51
for the layer a corporate support engineer spends the most time in.

### 0.9.14 — Tier 2 items 4 and 5: L2 rules, and bufferbloat offered by `why slow`

**L2: 2 rules → 6**

| Rule | Fires on | The distinction it protects |
|---|---|---|
| `link_negotiated_low_wired` | wired link under 100 Mbps | gigabit needs all four pairs; two damaged pairs fall back silently instead of failing |
| `dot1x_port_unauthorized` | 802.1X active, port Unauthorized, no explicit EAP failure | a port **held** by NAC is not a **rejected** credential, and the next step differs |
| `neigh_mostly_incomplete` | >5 neighbours, >60% never resolved | one unresolved neighbour is a host that is off; most of them is the segment |
| `wifi_open_network` | `wifi_key_mgmt = NONE` | no link-layer encryption, stated plainly |

All four fire on facts already collected. No new probes, nothing added to the
passive scan's cost.

**One new fact, and the false positive it exists to prevent**

`link_primary_is_wireless`, from the kernel on Linux (`/sys/class/net/<if>/
wireless`) and `MIB_IFROW.dwType == 71` on Windows — never from the adapter's
name, which is localised and user-renameable.

Without it, `link_negotiated_low_wired` is one of this project's classic
mistakes waiting to happen: **65 Mbps is a damaged cable on copper and an
ordinary afternoon on Wi-Fi.** The rule would have told laptop users to replace
a cable they do not have. Three selftest scenarios pin this — Wi-Fi at 65 must
not fire, wired at 10 must, and gigabit must be left alone — because a guard
that mutes the real fault along with the false one is not a guard.

**A rule I wrote and then deleted**

I added `link_half_duplex` at L2. `TestSeedRulesAgainstFixtures` failed
immediately: `duplex_mismatch` already matches `link_duplex: half`, at L1.
Two rules on one fact means the user reads the same problem twice under two
names, so mine came back out. The existing fixture discipline caught this
before it shipped, which is the second time this session that a test written
earlier has paid for itself.

(Worth noting for later: `duplex_mismatch` is tagged **L1** while duplex
negotiation is arguably L2. Retagging changes which `why` profiles surface it
via their `Layers` map, so it is not a free edit and was left alone
deliberately rather than overlooked.)

**`why slow` now names what it cannot see**

The passive walk measures loss, latency and DNS on an **idle** link.
Bufferbloat is invisible to all three by definition — the line looks perfect
until someone loads it — and it is the most common real answer to "calls break
up while someone uploads".

So `why slow` now ends by saying that out loud and pointing at `netdiag speed`.
Three deliberate boundaries:

- **An offer, never an auto-run.** `why slow` belongs to the read-only,
  costs-nothing promise; the load test deliberately fills the link and spends
  the user's data. Auto-running it here would quietly break the promise the
  rest of the tool is built on.
- **Silent when the walk already found something.** Burying a real finding
  under a pitch for a data-spending test is noise.
- **On Wi-Fi it also points at `why wifi`**, because the radio is the other
  usual answer and sending someone to buy a router for a signal problem is the
  same species of confident wrongness this project keeps fixing.

**Numbers**

- KB: 51 → 55 rules; L2 2 → 6
- `cmd/netdiag`: 7.1% → 8.5%; selftest scenarios 9 → 14 (18 checks total)
- all 11 test packages green, both build targets vet-clean

**Not done, and honest about it**

The remaining Tier 2 L2 work — VLAN-from-DHCP-scope mismatch, STP
topology-change storms, switch-port error counters via LLDP — is not a rules
problem. Every one of them needs data this tool does not collect: LLDP frames,
the DHCP scope's expected VLAN, spanning-tree state. Writing rules against
facts nothing produces would give the KB a bigger number and the user nothing,
which is the sort of trade this project exists not to make.

### 0.9.15 — Tier 2 item 6: `netdiag ticket`

    netdiag ticket                    # from a full scan
    netdiag ticket slow               # from the `why slow` walk
    netdiag ticket cant-reach fs01    # …with a target
    netdiag ticket -anon              # safe to paste outside the company
    netdiag ticket -o case-1234.txt

**What makes it a different renderer and not just another format**

The existing outputs answer "what did the tool find?". A ticket answers "what
does the next person need in order to not repeat my work?" — and that makes two
sections load-bearing that no other format has:

**RULED OUT** — the segments measured healthy, named explicitly. Without it,
tier 2 opens the ticket and re-tests the LAN that was already proved clean.
This is the section that turns the blame partition into somebody else's saved
hour, and it is the one a competing tool's export does not contain.

**NOT CHECKED** — every collector that skipped, errored or timed out, each with
its reason. A ticket is read by someone who was not there, who will act on it
without asking questions. Omit this and the document silently implies the whole
machine was examined. That is this project's oldest enemy wearing a new hat:
absence read as health, this time in the artefact most likely to be believed.

Segments that could not be judged get their own third section rather than being
folded into either — "not innocent, unmeasurable from here" — because an
unmeasured segment filed under RULED OUT is a lie the reader cannot detect.

**Design decisions worth recording**

- **Same collection path as `scan` and `why`.** Only the rendering differs. A
  second implementation of the diagnosis would be a second thing to be wrong.
- **Redact before rendering, never after.** Masking the finished text would
  mean a second masker that has to agree with the first one forever.
- **An unknown symptom is an error, not a fallback to a plain scan.** `why`
  degrades gracefully because the user is watching; a ticket would print
  "reported: <symptom>" above a walk that never examined it, and then be
  filed. Exit 2 instead.
- **Evidence is sorted.** A ticket that reorders its own evidence between runs
  cannot be diffed.

**A rendering bug caught before it shipped**

The shared `wrap()` hard-codes a 5-space continuation indent for the terminal
report. Reused here it turned `next: ` into a prefix repeated down the left
margin — unreadable, and worse, it made a pasted ticket look machine-mangled to
whoever received it. `hang()` now does a proper hanging indent, tested for
prefixing exactly once and losing no word. Section underlines also count runes,
not bytes: the em dashes in the titles ran the underline two characters past
the text.

**Numbers**

- `internal/report`: 90.5% → **92.4%**, 7 new tests
- 71-line ticket from a live run; wraps at 76 columns, no markdown
- all 11 test packages green, both build targets vet-clean, selftest 18/18

**Still open in Tier 2:** item 7, historical baselines — keeping the last N
instead of overwriting, so `-diff` can answer "what changed since Tuesday".

### 0.9.16 — Tier 2 item 7: historical baselines

    netdiag baseline              # saves, and keeps the last 10 here
    netdiag baseline -list        # what is kept, with dates
    netdiag -diff                 # vs the newest (unchanged behaviour)
    netdiag -diff -against 2      # vs the second newest
    netdiag -diff -against 2026-07-14
    netdiag -diff -against 7d

**The question it changes**

`-diff` could only ever answer "what changed since the last time someone
pressed save?" — a question whose answer silently got worse every time the tool
was used, because each save destroyed the comparison point. The question people
actually ask is "what changed since Tuesday, when it worked?", and that needs
more than one baseline to exist.

**Additive, not a migration**

`<key>.json` is still written exactly as before and is still what `Load()`
reads. History is a directory of timestamped copies *alongside* it. A baseline
saved by 0.9.15 keeps working; an older binary can still read one written
today. `TestSaveStillWritesTheLegacyBaseline` pins this, because an upgrade
that orphaned everyone's saved baseline would be a bad trade for a feature
nobody asked for yet.

**Three decisions that make a dated diff trustworthy**

- **Never substitute a different baseline than the one asked for.** If you ask
  for a year ago and the oldest kept is Tuesday, it fails and *says what is
  available*. Answering "what did it look like in January" with Tuesday's data,
  unlabelled, inverts the meaning of every line of the diff — a wrong diff is
  more dangerous than no diff, because it looks like evidence.
- **The date comes from the file contents, never the filesystem.** Copied,
  restored, or synced directories carry mtimes that lie. A baseline dated
  wrongly gets compared against the wrong day without ever saying so.
  `TestTimestampsComeFromContentsNotFileMtime` lies to the filesystem and
  asserts the answer does not move.
- **Which baseline was used is part of the answer.** Every diff header names
  the baseline and its date and age. "Nothing changed" means nothing without
  the date it is measured from.

Smaller ones: a history write failure never fails the save (the current
baseline is what matters, and losing it because a directory could not be
written would be worse than having no history); pruning keeps the *newest* ten,
which is the half that makes "since last week" possible; a corrupt file in the
history directory is skipped rather than counted as a baseline; and `-against`
takes what people type — `2`, `2026-07-14`, `7d` — with a bare date meaning the
*end* of that day, because someone typing the 14th means "as it was on the
14th", not one second past midnight.

**Numbers**

- `internal/baseline`: 59.1% → **70.3%**, 9 new tests
- all 11 test packages green, both build targets vet-clean, selftest 18/18
- 3 new menu entries; `baseline` verb now takes flags

**Tier 2 is complete.** Items 4–7 done: L2 rules, the bufferbloat offer, the
ticket export, historical baselines.

---

## Open, and honest about it

**RESOLVED in 0.9.17 — see the log.** The medium is now confirmed against a
second source, and every rule that depends on it refuses to fire unless the two
agree. The original debt, kept here because the reasoning is the point:

**`link_primary_is_wireless` on Windows.**
It reads `MIB_IFROW.dwType` at offset 516, reasoned from the documented layout
and never watched execute. Writing the verification sheet exposed why the lab
cannot close this: if the offset is wrong it reads some unrelated DWORD, none of
which equal 71, so a wrong offset looks like `false` on every machine — and the
only Windows box available is a virtio VM with no Wi-Fi, which can produce only
that weak `false`. The consequence if it is wrong: a Wi-Fi laptop at 65 Mbps
gets told to replace a cable it does not have.

The fix that does not need a Windows laptop is to stop trusting one unobservable
source — cross-check `dwType` against `netsh wlan show interfaces` naming the
same adapter, and emit nothing when the two disagree, so the rule cannot fire on
a guess. That is the next thing I would do, ahead of any Tier 3 item.

---

### 0.9.17 — the medium debt closed, and a usability pass

Two jobs, done without access to a Windows machine.

#### 1. `link_primary_is_wireless` no longer trusts one unobservable source

The problem, restated: `MIB_IFROW.dwType` is read at offset 516, reasoned from
documentation and never watched execute. A wrong offset reads an unrelated
DWORD, none of which equal 71, so it would report "wired" on *every* machine
including a Wi-Fi laptop — and the only Windows box available cannot detect
that, because a wired VM reporting `false` is exactly what a correct read also
produces.

Two independent sources cannot both be wrong in the same direction by accident.
So the Windows link collector now asks `netsh wlan show interfaces` whether the
primary adapter is in its list, and emits a second fact,
`link_medium_confirmed`, which is true **only when the two agree**.
`link_negotiated_low_wired` requires that confirmation, so an unconfirmed
medium blocks the rule rather than firing a guess.

The failure directions were chosen deliberately:

- netsh missing, or a locale whose adapter-name key we do not recognise → **not
  confirmed**. Costs a finding.
- struct says wired, netsh lists no wireless adapter at all → **confirmed
  wired**. This is the common case and stays free.
- the two disagree → **not confirmed**, and nothing is said.

An unconfirmed medium costs a finding. A wrong medium costs the user a new
cable and their trust in the tool. On Linux the kernel's own `/sys` answer is
authoritative — no offset to get wrong — so it is self-confirming, and the fact
exists on both platforms so rules need no OS branch.

`WlanInterfaceNames` is a pure parser with fixtures including French output,
because this is the **third** localisation bug family in this project and the
first two shipped. A locale we do not recognise yields no names, which makes
the medium unconfirmed rather than wrong.

New selftest scenario: *an UNCONFIRMED medium blocks the cable verdict
entirely* (19 checks now).

#### 2. Usability pass — the tool is only useful if it gets used

**The menu was 20 entries in one numbered wall.** Now four headed groups —
SOMETHING IS WRONG / WATCH AND COMPARE / LOOK AROUND / HAND IT OVER / TOOLS —
with the numbers unchanged, so anything written down still works. It also
accepts **text**: typing `print` or `slow` jumps to the entry, and an ambiguous
word lists the candidates. Making someone count rows is the kind of small
friction that stops a tool being picked up.

**A bare `netdiag` opened with a wall of evidence.** It now answers the actual
question in the first two lines — *"3 things are broken here, and one more is
worth a look"* plus the verdict — then the full report, then a **What next**
block naming the two verbs that make sense given what was found. The dense
report is evidence and stays; evidence without a summary makes someone read
forty lines to learn there is nothing to see.

The clean case still never says "all clear". It says *"Nothing failed the
checks below"*, and a test forbids the words *all clear*, *everything is fine*,
*no problems* and *healthy* in that line — because the not-checked list beneath
it is part of that sentence's meaning.

**Baselines spoke in storage keys.** `location "unknown-location"` and
`aa_bb_cc_dd_ee_ff` are correct identifiers and tell a reader nothing.
`Describe()` now names the network as a person would — *the Wi-Fi network
"corp-wifi"*, *the network behind gateway 192.168.1.1* — and a machine with no
gateway is told so, because that is usually **why** they are running the tool.

**`-diff` with no baseline was a dead end.** It said "run `netdiag baseline`
first" — telling someone their request failed and leaving them to fix it. Now
it offers to save one, there and then. It re-collects rather than reusing the
scan just shown, because the person is answering "is it healthy *now*", and an
unattended run reads EOF as "no" so nothing is ever saved by accident.

Also: `-diff` headers read *"vs the snapshot saved Mon 14 Jul, 09:12 (3 days
ago)"* rather than a raw key and timestamp; and `-list` prints copy-pasteable
examples instead of one terse hint.

**Numbers**

- `cmd/netdiag` 8.5% → **9.7%**, `collectors` 13.0% → **14.1%**
- selftest 18 → **19 checks**; 3 new cmd tests, 1 new parser test with French
  fixtures
- all 11 packages green, both targets vet-clean

---

## Further steps, in the order I would take them

**1. Verify the medium on a real Windows Wi-Fi machine when one is available.**
The cross-check makes a wrong offset *harmless* rather than *impossible* — it
now costs a finding instead of giving bad advice. One run on a Wi-Fi laptop
would let `link_medium_confirmed` be true in the common case rather than
falling back to silence. Not urgent any more; it was the top of this list
before 0.9.17, and it is now an optimisation.

**2. Take `collectors` past 25%.** Still the biggest package and the least
tested. The parsing surfaces named earlier remain: `wevtutil` event mining,
`netsh advfirewall`, `certutil` CA scanning, journalctl/syslog mining, and the
WEXT byte decoding. Same pattern that worked twice already — extract the pure
parser, feed it captured real output.

**3. Split the three grab-bag files.** `collectors_windows.go` is now ~1,250
lines, `walk.go` 670, `main.go` ~700 and growing with every usability
addition. This is the first item that is purely about the next person's
ability to work on it.

**4. Upload bufferbloat (Tier 3 item 10).** Only download is measured, and
upload saturation is the one that actually breaks video calls. The measurement
machinery already exists; it is a second direction, not a new subsystem.

**5. Signed Windows binary (Tier 3 item 8).** Needs a real certificate in your
name. Until then SmartScreen frightens exactly the users who most need to be
reassured the tool is safe.

**Deliberately still not doing: a GUI.** The menu now has headings and text
search, which was most of the value a window would have added, at none of the
cost to the single-static-binary property.

---

### 0.9.18 — further step 2: collectors past 25%, and two more bugs

`collectors` 14.1% → **25.2%**. Same method as 0.9.11: extract the pure
parsing, feed it captured real output. Two shipped bugs fell out of writing the
tests, which is now the fourth and fifth time that has happened.

**Bug #23 — the firewall policy was a default, not a measurement**

`inputPolicy` was initialised to `"accept"` and only ever revised to `"drop"`.
A ruleset that never states an input policy — an nft config doing only NAT, for
instance — was therefore reported as **"input policy accept"**: a fact nobody
measured, printed beside facts that were. Someone reading that in a ticket
concludes the host firewall is wide open and goes looking for the wrong
problem.

`SummariseNftables` / `SummariseIptables` now report whether the policy was
actually stated, and the fact is **omitted** when it was not — every renderer
already knows how to show a missing fact as not-measured. `reject` is also
recognised now; it is a real nft policy that used to read as accept, which
inverted the meaning entirely.

**Bug #24 — a finding that fired on every Linux machine**

Writing the hosts-file test showed `fe00::0 ip6-localnet` being reported as a
manual override. It is neither loopback nor multicast, so filtering by address
class missed it — and it ships in `/etc/hosts` on Debian, Ubuntu, Zorin, Fedora
and the rest. **Every Linux machine reported a deliberate hosts override it did
not have.**

The damage is subtler than a wrong answer: a finding that fires everywhere is a
finding people learn to scroll past, including on the one machine where it is
real. The filter now judges by NAME, because the name is what makes the line
boilerplate. A regression test feeds it a stock distro hosts file and requires
zero findings; a second test feeds it a real IPv6 override and requires it to
still be caught, because a filter that went too far the other way would be the
same bug with the sign flipped.

**What is now tested that was not**

The event miner (`MineEvents`) — the tier that answers "it drops now and then",
and the one that found 126 link flaps on the Zorin laptop — had no tests at
all. Its phrase list *is* the detector: a distribution that words a carrier
loss differently produces a silent zero, which reads as "this link is stable".
Now fixtured, including the alternate spellings and the syslog case that
carries no timestamp and must count without being bucketed into 1970.

Also newly covered: DHCP lease parsing (dhclient appends, so taking the first
`expire` reports a lapse from months ago on a healthy machine), `plausibleIPv4`
(moved out of the Windows-only file — the "255" bug it was written for deserves
a test that runs everywhere), Wi-Fi channel/band decoding including 6 GHz,
resolver disagreement ignoring dead resolvers, proxy credential stripping,
`peakHour`, and `sysReadInt` — where an absent sysfs file must stay negative,
because a NIC reporting 0 Mbps and a NIC that cannot report are different
machines.

**Numbers**

- `collectors` 14.1% → **25.2%** (the whole-suite figure reads 24.6%; the
  difference is Linux-only files that do not compile into the cross-platform
  run)
- 12 new test functions, ~330 lines, fixtures from the field campaign
- all 11 packages green, both targets vet-clean, selftest 19/19

---

### 0.9.19 — three bugs from one field run on the Zorin laptop

A single `netdiag -diff -against 7d` plus a `why slow` on popeye-mk's laptop
produced three. Bug #24 was confirmed fixed in the same run (`grep
hosts_file_override` returned nothing).

**Bug #25 — the all-clear stood above four visible faults. Bug #7's family.**

The scan printed:

> All 3 measured segments are healthy — whatever the user saw is **not visible
> from this machine right now**.

directly above a layer report showing **L1 ✗, L3 ✗, L7 ✗**: 126 link flaps, a
1380 path MTU, a dead IPv6 path, LLMNR exposed. Every one of them visible from
that machine, at that moment, in the same output.

The cause: the amendment added for bug #7 fired only on **critical** findings.
Four warnings left the qualifier standing untouched. The fix that closed #7 was
correct and too narrow — a warning is, by definition, something the tool CAN
see, so it cannot coexist with "not visible from this machine". Only info-level
notes are quiet enough to leave the all-clear alone.

Widened in three places that must stay in step: the scan path, the selftest
harness, and the pipeline test. The harness matters most — it exists to catch
the scan path lying, and a harness modelling an older version of that path
cannot do that. New selftest scenario (20 checks now) pins it with the exact
shape of this run: healthy transport, a broken dual-stack, and a verdict
forbidden from claiming invisibility.

**Bug #26 — the tool contradicted itself in one screen**

The headline said *"4 things are worth a look"* above a section headed
**Findings (6)**. It counted warnings and silently dropped the two info notes.
Two numbers for one list teaches the reader that the summary cannot be trusted,
which costs more than the summary is worth. The headline now accounts for
every finding and states the total.

**Bug #27 — a failed check phrased as a passing one**

The `why slow` verdict read:

> First break in the walk → L3: **path MTU sane** — 1380 — tunnel-grade; large
> packets may black-hole

Check labels are written as assertions ("path MTU sane", "IPv6 not
half-broken") because they read well beside a ✓. Pasted into a verdict after a
✗ they invert, and the sentence tells the reader the MTU is fine in the same
breath as saying it is not. The verdict now leads with the failure detail and
keeps the label as a parenthetical subject.

**Also fixed:** a malformed `-against` used to be reported *after* a full scan,
at the bottom of forty lines of report. It is knowable before anything is
collected, and now fails in 3 ms — making someone sit through a scan to be told
"last tuesday" is not a date wastes the one resource this tool exists to save.

**What the run also confirmed working**

`why slow` correctly withheld the bufferbloat offer, because the walk had
already found something — the suppression rule from 0.9.14 doing its job on a
real machine. `-diff -against 7d` correctly refused to substitute a nearer
baseline and named the oldest it had.

**Numbers**

- selftest 19 → **20 checks**
- all 11 packages green, both targets vet-clean

Three of the last four bugs in this project were **the tool being confidently
wrong in its summary line** rather than wrong in its measurements. The
measurements on that laptop were all correct. Every sentence built on top of
them was where the errors were.

### 0.9.20 — the fix for #25 was itself wrong, in the way #25 was wrong

popeye-mk's re-run of 0.9.19 showed the widened verdict working and saying
something false:

> the transport path (this machine, LAN, WAN) is healthy, but **the fault is
> above it** — The link went down repeatedly in the last 24 hours … without a
> long-running capture**..**

**Bug #28 — "above it" was inherited from a narrower case.**

That sentence was written for bug #7, where the finding genuinely *was* above
the transport path: a bad resolver, a missing SRV record, config faults that
leave L1–L4 green by definition. Widening the trigger to warnings (bug #25)
handed the same sentence to a finding at **L1**. 127 link flaps are not above
the transport path — they *are* the transport path. They were invisible for a
different reason: they already happened, and an instantaneous measurement
cannot see last night.

Fixing the trigger without re-reading the sentence it triggers is the same
mistake as #25 one level up: a claim that was true in the case it was written
for, quietly reused where it is false.

The verdict now makes only the claim that is always true — *"all measured
segments are healthy right now, but that is not the whole picture"* — and names
the finding without asserting where it sits.

**Bug #29 — the headline swallowed a whole paragraph.**

Finding text is written to be complete, which is right in the findings list and
wrong in a one-line verdict: the link-flap rule ran to three clauses and ended
with a stray double full stop (`capture..`). `firstSentence()` keeps a headline
to a headline.

**Bug #27 was only half-fixed in 0.9.19.**

The verdict got the corrected phrasing; the "First break in the walk →" line
four rows below it did not, so the same run showed both wordings. They now go
through one `breakLine()` helper and cannot disagree again — the same lesson as
the selftest harness in #25: two places rendering one idea will drift, and the
drift is silent.

**On the test updates.** Four tests asserted the old sentence. I changed the
expected strings and kept every property: the verdict must still not read as an
all-clear, must still name the finding, and the walk must still report the
first failure and not a later one. A test updated to match new behaviour is
only honest if the behaviour it was protecting is still protected — so
`TestWalkFirstBreak` gained two assertions rather than just having its string
swapped.

**Numbers**

- selftest 20/20, all 11 packages green, both targets vet-clean

**The pattern, now four bugs deep:** #25, #26, #27, #28 and #29 were all the
tool's *sentences* being wrong while its *measurements* were right. Every
number on that laptop was correct in every run. The verdict layer is where this
project's remaining risk lives, and it is thin on tests precisely because it
reads as prose rather than logic.

### 0.9.21 — bug #30, and the install that made an old binary look like a new one

**Two problems, one `why wifi` run on the Zorin laptop.**

**The run was against a pre-0.9.20 binary.** The verdict still said "the fault
is above it" and the walk still used the old first-break format, both replaced
in 0.9.20. The cause is boring and worth fixing properly: an earlier
`sudo ./install_linux.sh` had put netdiag in `/usr/local/bin`, which sits
ahead of `~/.local/bin` on most PATHs. Typing `netdiag` ran the old one while
the desktop icon ran the new one.

An afternoon of testing a build you did not install is a bad outcome for a
tool whose entire value is being trustworthy about what it observed.
`install_desktop.sh` now detects another netdiag earlier on the PATH, prints
both versions and both paths, and says which one the command will actually
run.

**Bug #30 — correct measurement, wrong medium.**

On a laptop with no ethernet port, `why wifi` reported 21 wireless disconnects
and then advised:

> Correlate flap times with activity (dock/undock, PoE load, backup jobs);
> **check cable and switch port.**

and in plain language: *"This points to a loose cable, a failing port…"*

`link_flaps_24h` counts `link is down` and `carrier lost` from the system log,
which is exactly what a Wi-Fi disconnect writes. The counter was right and
medium-agnostic; the advice attached to it was written for copper only.

**Deliberately not split into wired/wifi rules.** The engine has eq/gt/lt and
no "fact absent" matcher, so any medium-conditional split leaves a machine
whose medium is unknown or unconfirmed matching *nothing at all* — and on
Windows, "unconfirmed" is a state the tool reaches on purpose (see 0.9.17).
Twenty-one drops and silence is a worse answer than twenty-one drops and
advice covering both media. The rule now names both causes and points at
`why wifi` / `why intermittent` to narrow it.

Because the fix is entirely wording, the test asserts wording: the advice must
mention Wi-Fi, must still mention cables, and must not contain the two phrases
that asserted a wired cause unconditionally. Nothing else would catch this
regressing. It also asserts the rule still fires on wireless, wired, **and
unknown** media — the last one being the reason it is a single rule.

**Numbers**

- selftest 20 → **21 checks**
- all 11 packages green, both targets vet-clean

**Six of the last seven bugs have been the tool's advice or summary being
wrong while its measurements were right.** #30 is the purest example so far:
the number 21 was correct, the sentence next to it sent a laptop user looking
for a cable that does not exist on the machine.

### 0.9.21a — the launcher I shipped without launching

Clicking the desktop icon printed:

```
sh: 1: netdiag: not found
```

`netdiag-window` called a bare `netdiag` and relied on PATH. A terminal spawned
from a desktop icon does not inherit the PATH that `~/.profile` builds at
login, and `~/.local/bin` is often only added there conditionally — so the
launcher looked for the binary in an environment that had never heard of it.
The installer knew the absolute path all along. **Asking PATH to find it again
was a guess where a fact was available**, which is the same error this project
keeps finding in its own verdicts, this time in its own plumbing.

**The real failure was in how I tested it.** I ran the installer into a
throwaway HOME and checked that five files appeared, that the shell syntax
parsed, and that the binary at the install path reported its version. All true,
all green, and none of it touched the code path that actually runs when a
person clicks the icon. I verified the *artefacts* and called it verification
of the *behaviour*.

That is precisely the mistake the tool exists to prevent — "I looked and it is
fine" versus "I did not look at the thing that matters" — and I made it in the
work verifying the tool. The fix is now tested by running the launcher with
`env -i` and a PATH containing no netdiag at all: the failure condition
reproduced first, then the fix confirmed against it.

The launcher also falls back to `command -v netdiag` if the absolute path is
gone, and shows a zenity error rather than dying silently behind a window that
has already closed.

### 0.9.22 — bug #31: whose link went down?

`why wifi` on the Zorin laptop reported 21 wireless disconnects and, beside
them, a finding saying the link had "gone down repeatedly" 127 times. Two
counts for one machine, six times apart. The journal settled it:

```
46 enp7s0:
jul 19 18:05:35 kernel: r8169 0000:07:00.0 enp7s0: Link is Down
```

**Every one of them was the ethernet port.** The laptop was on Wi-Fi. `r8169`
logs a link-down for an empty socket, all day, forever — so the tool was
reporting an unplugged cable as the machine's connection failing, on a machine
whose connection was fine.

`MineEvents` counted every "link is down" line in the log regardless of which
interface it named. The count was correct. **The subject of the sentence was
wrong** — the same species as #30 one step earlier in the pipeline, and the
seventh consecutive bug of that shape.

**The fix.** Flaps are now attributed to the interface owning the default
route — the one actually carrying traffic, not "the first interface that is
up", which on this laptop would have picked the unplugged port and hidden the
bug for another month. Three outcomes, all stated rather than assumed:

| | |
|---|---|
| flap on the primary | counts, and can fire `link_flap_history` |
| flap on any other interface | reported separately as `idle_iface_flapping` (info) |
| no primary knowable | counted but marked **unattributed**, and the accusing rule cannot fire |

The third row is the important one. Silence would hide a real fault;
attribution would invent one. So the number stays visible as evidence while
the claim built on it is withheld — which is this project's oldest rule
applied to its own counter.

Windows has the same problem and cannot currently answer it: the event query
there is not per-adapter, so it now reports `link_flaps_attributed = false`
and the rule stays quiet. That costs a finding on Windows and is the correct
trade.

**A new rule rather than silence.** `idle_iface_flapping` (info) says an unused
port is flapping and that it is normal — because "my cable does nothing" is a
real ticket and this is the evidence for it. Deleting the information would
have been the easy fix and the wrong one.

**Two parser mistakes worth recording**, both caught by tests rather than by
reading:

- Splitting on the last colon to find the interface name yields `0000:07` from
  `r8169 0000:07:00.0 enp7s0:` — the PCI id is full of colons. The comment in
  the code now says so explicitly, because it looks correct.
- `igb: enp1s0 NIC Link is Down` filed `NIC` as an interface. The name must be
  the token the message is *attached* to, so it has to end with the colon.

**I corrected the project's own record.** The header of this document listed
"126 link flaps" among six genuine faults found on unplanted machines. It was
a false positive, as were the hosts-file overrides (#24). Two of the six
headline pieces of evidence that this tool works were wrong, and both survived
because I cited the finding without reading its evidence — the exact failure
the tool is built to prevent in others.

**Numbers**

- selftest 21 → **22 checks**; KB 55 → 56 rules
- 4 new parser tests, all 11 packages green, both targets vet-clean

### 0.9.23 — first live runs of the elevated tier and watch mode, and bug #32

**Both never-run-live features passed on the Zorin laptop.**

`sudo netdiag` — the firewall collector's first execution against a real
ruleset, including the bug #23 path: it read the rules, invented no policy, and
the "Not checked" section disappeared entirely because everything ran. The
bug #31 fix also showed live: 45 flaps of the idle ethernet port appeared as an
info note saying to ignore them, with no accusation against the machine's link.
Headline arithmetic matched its own findings list (3 + 2 = 5).

`watch -duration 10m` — popeye-mk induced a fault mid-watch, and the timeline
caught the entire arc with timestamps: DNS failing first, the link going down,
the address flipping to 10.0.0.1 and back, recovery, and the 263 ms DNS lag
that followed. The summary judged it against the location's saved baseline.
This is the v1.3 feature doing, on real hardware, exactly the job it was
specified for.

**Bug #32 — a note the tool said to ignore rendered as a fault.**

Same sudo run, layer report:

```
L1  Physical     ✗  An interface that is NOT carrying this machine's traffic...
```

The `idle_iface_flapping` note's own text says "normally ignore it" — and the
layer report marked L1 with a ✗, because the marks treated every finding at a
layer as damage. A ✗ is a claim of a fault; info is by definition not one.
Layers with only notes now render as:

```
L1  Physical     i  no fault — but note: An interface that is NOT carrying...
```

The regression test asserts both directions: an info-only layer must not show
✗, and a warning at the same layer still must — a fix that softened real
findings would be worse than the bug.

**Numbers:** selftest 22/22, all packages green, both targets vet-clean.

**Testing status after this round:** every feature has now had at least one
live run on Zorin, including the elevated tier and watch. The one platform gap
that remains is Windows at 0.9.13+ — verified at 0.9.12, cross-compiled and
fixture-tested since. Bugs #24–#32: nine consecutive findings-layer bugs,
zero measurement bugs. The counters have been right since 0.9.11.

### 0.9.24 — bug #33: a dictionary read as a diagnosis

popeye-mk opened the offline reference (menu 20), looked up "port", and asked:
*"are these ports open by me?"* Reasonable question — the screen showed a list
of ports with security notes ("poisoning vector", "legacy, plaintext") and
nothing saying it was a lookup table rather than a result. A reference that can
be mistaken for a scan is a wrong scan waiting to be acted on: the next reader
firewalls forty ports that were never open.

Every `ref` lookup now leads with three lines saying it is a reference, the
same on every machine, and where to see this machine's actual ports. The test
asserts the disclaimer is the first thing on screen for every lookup form.

selftest 22/22. Bugs #24–#33: ten consecutive presentation-layer bugs, zero
measurement bugs.

### 0.9.25 — the menu now admits what else exists

popeye-mk looked at the 20-entry menu and asked where the rest of the
functionality was. Right question. `compare` — the two-machine workflow, save a
snapshot on the working machine and the broken one and rank the differences —
was CLI-only and invisible, despite being one of the strongest daily-support
moves the tool has. It is now menu entry 14; an empty answer at its prompt
prints the two-machine recipe instead of an error, because the workflow spans
machines and the person at the prompt may be on the first of them.

`-json`, `-anon`, `-kb` and `-since` stay CLI-only deliberately — they are
scripting surface, and a menu that lists every flag stops being the simple
front door that was the point. The quick start now names them so they are
discoverable without being in the way. Doc numbers re-verified against the
live menu after the shift.

selftest 22/22, all packages green.
