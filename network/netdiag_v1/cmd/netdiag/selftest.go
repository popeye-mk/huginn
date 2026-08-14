package main

// `netdiag selftest` — the answer to "do I trust this build?"
//
// It runs no probe, reads no system state and touches no network. It pushes
// fixed facts through the real rules engine, the real blame logic and the real
// renderer, and checks the sentences that come out against the verdicts this
// tool has been caught getting wrong in the field.
//
// Why a VERB and not just a unit test: unit tests prove the build was good on
// the machine that compiled it. This proves the binary in the customer's hand
// is good — after a USB copy, an antivirus quarantine-and-restore, or a field
// tech hand-editing kb.json at 2am. It also validates an external KB, which no
// unit test ever sees.

import (
	"flag"
	"fmt"

	"netdiag/internal/selftest"
)

func selftestCmd(args []string) int {
	fs := flag.NewFlagSet("selftest", flag.ContinueOnError)
	kb := fs.String("kb", "", "validate an external knowledge base instead of the embedded one")
	quiet := fs.Bool("quiet", false, "print only the summary line (for scripts and logon checks)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	results := selftest.Run(*kb)
	ok, failed := selftest.Passed(results)

	if *quiet {
		if ok {
			fmt.Printf("netdiag %s selftest: %d/%d passed\n", toolVersion, len(results), len(results))
		} else {
			fmt.Printf("netdiag %s selftest: %d of %d FAILED\n", toolVersion, failed, len(results))
		}
	} else {
		fmt.Print(selftest.Render(results, toolVersion))
	}

	// Exit code is the contract: 0 means the reasoning is intact, 1 means do
	// not believe this binary's verdicts. Scripts and imaging pipelines gate
	// on it.
	if ok {
		return 0
	}
	return 1
}
