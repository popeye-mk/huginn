# Contributing to Huginn

Thanks for looking. Huginn is small, opinionated, and built to a single
rule — contributions are welcome as long as they keep to it.

## The one rule

> **Absence is never health.** A check that could not run must never look
> like a check that passed.

Anything that reports "all clear" when it actually means "I could not tell"
will be sent back. Findings carry coverage; missing tools degrade honestly
and say so. This is the whole point of the project, and the tests enforce
it — see `ops-platform/tools/test_architecture.py`.

## Ground rules the tests enforce

You do not have to memorise these; the test suite will tell you if you break
one. But knowing them saves a round-trip:

- **Detect and propose, never act.** No code path blocks, disconnects, or
  changes a network setting. A test parses for it.
- **Zero dependencies.** Huginn runs on the Python standard library alone
  (netdiag on the Go standard library). Do not add a `pip`/`go get`
  requirement to the core.
- **One place for OS differences.** Every OS branch lives in
  `platform_support/`. A portability test fakes each OS to prove it.
- **Layers point downward only**, files stay under 400 lines, functions
  under ~50, subprocess only in `engines/`.

## Running the tests

```bash
cd ops-platform
python3 tools/test_architecture.py            # the structural rules
for f in tools/test_*.py; do python3 "$f"; done   # the full battery
```

Green locally is green in CI. Please add or update a test with any change
in behaviour — a fix without a test is a fix that comes back.

## Opening a change

1. Fork, branch, make the change **with a test**.
2. Run the two commands above; make sure they pass.
3. Open a pull request describing *what changed and why*. If it touches a
   detector, say what it can and cannot see — honesty about limits is a
   feature here, not a caveat.

## Reporting a problem

If Huginn does something the docs say it will not — especially if it ever
reports "all clear" when it should have said "not checked" — that is the
most important kind of bug. Open an issue with what you ran and what you saw.

## License

By contributing, you agree your work is licensed under the project's
**GNU AGPLv3** (see [`LICENSE`](LICENSE)) — the same terms that keep Huginn
free and open for everyone downstream.
