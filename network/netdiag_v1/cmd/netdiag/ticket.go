package main

// `netdiag ticket [symptom] [target]` — the handover artefact.
//
//	netdiag ticket                    # from a full scan
//	netdiag ticket slow               # from the `why slow` walk
//	netdiag ticket cant-reach fs01    # …with a target
//	netdiag ticket -anon              # safe to paste outside the company
//	netdiag ticket -o case-1234.txt   # straight to a file
//
// Same collection path as `scan` and `why`; only the rendering differs. A
// second implementation of the diagnosis would be a second thing to be wrong.

import (
	"flag"
	"fmt"
	"os"

	"netdiag/internal/collectors"
	"netdiag/internal/interpret"
	"netdiag/internal/report"
	"netdiag/internal/run"
	"netdiag/internal/triage"
)

func ticketCmd(args []string) int {
	fs := flag.NewFlagSet("ticket", flag.ContinueOnError)
	out := fs.String("o", "", "write to this file instead of stdout")
	anon := fs.Bool("anon", false, "redact addresses, MACs and hostnames before writing (§4.3)")
	kbPath := fs.String("kb", "", "path to an external rules.json")
	since := fs.Int("since", 24, "event-history window in hours")

	var symptom, target string
	rest := args
	if len(rest) > 0 && rest[0][0] != '-' {
		symptom, rest = rest[0], rest[1:]
	}
	if len(rest) > 0 && rest[0][0] != '-' {
		target, rest = rest[0], rest[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	collectors.EventWindowHours = *since

	rules, kbSource, err := interpret.LoadRules(*kbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "kb error:", err)
		return 2
	}

	// An unknown symptom must not silently become a plain scan: the ticket
	// would then say "reported: <something>" over a walk that never looked at
	// it. Name the mistake and stop.
	var prof triage.Profile
	if symptom != "" {
		p, known := triage.Profiles()[symptom]
		if !known {
			fmt.Fprintf(os.Stderr, "unknown symptom %q\nknown: %s\n",
				symptom, joinNames(triage.Profiles()))
			return 2
		}
		prof = p
	}

	stopProgress := startProgress()
	snap := run.All(collectors.ForThisOS(), toolVersion)
	stopProgress()
	facts := snap.Facts()

	if symptom != "" && prof.Prepare != nil {
		fmt.Fprint(os.Stderr, "  probing the target … \r")
		prof.Prepare(facts, target)
	}

	findings := interpret.Evaluate(rules, facts)
	blame := triage.Blame(facts, prof.DCLabel)
	firstBreak := ""
	if symptom != "" {
		firstBreak = prof.FirstBreak(facts)
		blame.NoteUnattributed(firstBreak)
	} else {
		for _, f := range findings {
			if f.Severity == "critical" {
				blame.NoteUnattributed(f.Finding)
				break
			}
		}
	}

	// Redact BEFORE rendering. Redacting the finished text would mean writing
	// a second masker that has to agree with the first one forever.
	if *anon {
		snap.Redact()
	}

	segs := make([][3]string, 0, len(blame.Segments))
	for _, s := range blame.Segments {
		segs = append(segs, [3]string{s.Name, s.Status, s.Evidence})
	}

	text := report.RenderTicket(report.Ticket{
		Snapshot: snap, Findings: findings,
		Symptom: symptom, Target: target,
		Verdict: blame.Verdict, Segments: segs,
		FirstBreak: firstBreak, KBSource: kbSource,
	})

	if *out == "" {
		fmt.Print(text)
	} else if err := os.WriteFile(*out, []byte(text), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "write error:", err)
		return 1
	} else {
		fmt.Printf("  ticket written to %s\n", *out)
	}
	return exitCode(findings)
}

func joinNames(m map[string]triage.Profile) string {
	names := profileNames(m)
	s := ""
	for i, n := range names {
		if i > 0 {
			s += ", "
		}
		s += n
	}
	return s
}
