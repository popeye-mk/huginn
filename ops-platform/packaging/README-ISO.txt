Huginn - Windows 11 verification disc
========================================

WHAT THIS IS

  A test disc, not an installer. It runs the Huginn test suite on this
  Windows machine and writes a report to your Desktop.

  Nothing is installed. Nothing on this machine is changed. No network
  access is used and nothing is downloaded.


HOW TO RUN IT

  1. Attach this ISO to the VM as a DVD drive
       Hyper-V Manager -> Settings -> SCSI Controller -> DVD Drive -> Image file
       (or right-click the .iso in Windows and choose Mount)

  2. Open the drive and double-click  VERIFY.cmd

  3. Wait. It takes a minute or two.

  4. Find  huginn-windows-report.txt  on your Desktop.


WHAT IT NEEDS

  Python 3.9 or newer.  Verified on 3.14.6.

    pip install pyyaml numpy

  An earlier version of this file claimed "nothing else, no pip install".
  That was wrong, and the first real Windows run proved it:

    - pyyaml  Diagnostic Companion's knowledge base is YAML, so its CLI
              and its fleet module will not import without it. Without
              pyyaml, 3 smoke checks and 2 suites cannot run.
    - numpy   Semantic recall only. Everything else degrades cleanly and
              says so.

  Both were installed system-wide on the Linux machine this was built on,
  which is exactly why the false claim survived until Windows tested it.

  The disc reports missing dependencies by name before running anything,
  and suites that need them are reported as SKIPPED - never as passed.

  If Python is missing, VERIFY.cmd will say so and stop. Note that the
  "python3" Windows offers by default is a Microsoft Store placeholder,
  not an interpreter. Install a real one:

      winget install -e --id Python.Python.3.12

  or from https://www.python.org/downloads/windows/ with "Add python.exe
  to PATH" ticked.


WHAT IT IS ACTUALLY CHECKING

  The Linux test results cannot answer these, structurally:

    - does netdiag resolve netdiag_windows_amd64.exe rather than skipping
    - does platform_support select Hyper-V rather than KVM
    - does Diagnostic Companion run under Windows Python
    - does anything behave differently from the Linux baseline

  Linux baseline for comparison: smoke test 13 passed, 0 failed,
  0 skipped.


WHAT IT IS NOT CHECKING

  Being straight about the gaps, because a verification disc that
  overstates itself is worse than none:

    - The Anora assistant is NOT on this disc. It needs requests, numpy
      and a model download; including it would turn a zero-dependency
      check into a pip install. Her integration tests are Linux-verified
      and stay that way for now.

    - No real backup is restored. There is no restic repository here.
      The backup suite proves the reasoning with faked engines; it does
      not prove the plumbing.

    - No VM is created. HyperVSandbox reports whether Hyper-V is present
      and usable, but a real boot test is a separate, later exercise.

  A check that could not run is reported as failed, never skipped into
  silence. An unavailable engine reported green would be exactly the
  "absence looks like health" failure this platform exists to prevent.


AFTERWARDS

  Delete  %LOCALAPPDATA%\huginn-verify  and nothing remains.
