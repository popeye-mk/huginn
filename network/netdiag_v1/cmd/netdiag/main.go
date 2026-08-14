// netdiag v1.1 — the "why can't I reach X" + blame-partition release
// (spec v2.3 §18 v1.1): the `why` triage layer-walks (§6, §6.1, §6.4), the
// blame-partition verdict as the headline of every run (§8), plain-language
// `--for-user` rendering (§6.2), and the local append-only `feedback` verb
// (§5.3). Still one static binary, stdlib only, passive/self-scoped.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"netdiag/internal/baseline"
	"netdiag/internal/collectors"
	"netdiag/internal/feedback"
	"netdiag/internal/interpret"
	"netdiag/internal/ref"
	"netdiag/internal/report"
	"netdiag/internal/run"
	"netdiag/internal/schema"
	"netdiag/internal/triage"
	"netdiag/internal/watch"
)

const toolVersion = "0.9.25-v1.5"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "ref":
			fmt.Print(ref.Lookup(os.Args[2:]))
			return
		case "feedback":
			os.Exit(feedbackCmd(os.Args[2:]))
		case "why":
			os.Exit(whyCmd(os.Args[2:]))
		case "baseline":
			os.Exit(baselineCmd(os.Args[2:]))
		case "compare":
			os.Exit(compareCmd(os.Args[2:]))
		case "watch":
			os.Exit(watchCmd(os.Args[2:]))
		case "devices", "discover":
			os.Exit(devicesCmd(os.Args[2:]))
		case "ticket":
			os.Exit(ticketCmd(os.Args[2:]))
		case "selftest":
			os.Exit(selftestCmd(os.Args[2:]))
		case "speed", "bufferbloat":
			os.Exit(speedCmd(os.Args[2:]))
		case "menu", "help", "--help", "-h":
			os.Exit(menuCmd())
		}
	}
	os.Exit(scanCmd(os.Args[1:]))
}

// -------------------------------------------------------- baseline (§5.2)

func baselineCmd(args []string) int {
	fs := flag.NewFlagSet("baseline", flag.ContinueOnError)
	list := fs.Bool("list", false, "list the baselines kept for this location instead of saving one")
	keep := fs.Int("keep", baseline.DefaultKeep, "how many historical baselines to retain here")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	stopProgress := startProgress()
	snap := run.All(collectors.ForThisOS(), toolVersion)
	stopProgress()
	facts := snap.Facts()

	if *list {
		fmt.Print(baseline.RenderHistoryFor(baseline.History(facts), facts))
		return 0
	}

	key, err := baseline.Save(snap, facts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "baseline error:", err)
		return 2
	}
	fmt.Printf("Saved how %s looks while it is working.\n", baseline.Describe(facts))
	if *keep != baseline.DefaultKeep {
		_ = baseline.SaveHistory(snap, key, *keep) // re-prune to the requested depth
	}
	kept := len(baseline.History(facts))
	fmt.Printf("\n  Next time something breaks here, run:  netdiag -diff\n")
	fmt.Printf("  and it will show you what changed since now.\n")
	if kept > 1 {
		fmt.Printf("\n  %d snapshots kept for this network (`netdiag baseline -list` shows the dates).\n", kept)
	}
	return 0
}

// --------------------------------------------------------- compare (§7.1)

func compareCmd(args []string) int {
	if len(args) < 2 {
		fmt.Println("usage: netdiag compare good.json bad.json   (snapshots from `netdiag -save`)")
		return 2
	}
	good, err := baseline.LoadSnapshotFile(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	bad, err := baseline.LoadSnapshotFile(args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	goodFacts, badFacts := good.Facts(), bad.Facts()

	fmt.Printf("netdiag v1.2 — compare %s (working) → %s (broken)\n", args[0], args[1])
	fmt.Println(strings.Repeat("─", 72) + "\n")
	if good.OS != bad.OS {
		fmt.Printf("  Honest limit: different OSes (%s vs %s) — expect benign differences.\n\n", good.OS, bad.OS)
	}
	changes := baseline.Diff(goodFacts, badFacts)
	fmt.Print(baseline.Render(changes, fmt.Sprintf("%s → %s", args[0], args[1])))

	// Rules firing on the broken machine but not the working one — the KB's
	// half of the "interpreted delta" (§7.1).
	if rules, _, err := interpret.LoadRules(""); err == nil {
		goodIDs := map[string]bool{}
		for _, f := range interpret.Evaluate(rules, goodFacts) {
			goodIDs[f.ID] = true
		}
		var extra []interpret.Finding
		for _, f := range interpret.Evaluate(rules, badFacts) {
			if !goodIDs[f.ID] {
				extra = append(extra, f)
			}
		}
		if len(extra) > 0 {
			fmt.Printf("\n  Findings on the broken machine that the working one does not have (%d):\n", len(extra))
			for i, f := range extra {
				fmt.Printf("  %d. [%s|%s] %s (rule: %s)\n", i+1, f.Layer, f.Severity, f.Finding, f.ID)
			}
		}
	}
	if len(changes) > 0 {
		return 1
	}
	return 0
}

// ------------------------------------------------------------- watch (§9)

// watchCmd is the time-domain mode: a BOUNDED run you start and read, never a
// daemon (§14 draws that line deliberately). It samples the cheap passive
// facts on an interval, prints each interpreted event the moment it fires,
// and closes with the timeline + rhythm + verdict. Ctrl-C ends the run early
// and still prints the summary — an interrupted watch must never lose the
// evidence it already gathered.
func watchCmd(args []string) int {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	duration := fs.Duration("duration", 10*time.Minute, "how long to watch (e.g. 30m, 2h)")
	interval := fs.Duration("interval", 10*time.Second, "seconds between samples (minimum 3s)")
	jsonOut := fs.Bool("json", false, "emit samples + events as JSON at the end")
	quiet := fs.Bool("quiet", false, "suppress the live event lines; print only the summary")
	savePath := fs.String("save", "", "write the full watch record (samples + events) to this file")
	_ = fs.Parse(args)

	if *interval < 3*time.Second {
		*interval = 3 * time.Second // below this the sampler overlaps itself
	}

	// Baseline-aware (§5.2): judge against what is normal AT THIS LOCATION.
	normal := watch.Normal{}
	probe := run.Only(collectors.ForThisOS(), watch.SampleCollectors, toolVersion)
	probeFacts := probe.Facts()
	if base, savedAt, key, err := baseline.Load(probeFacts); err == nil {
		bf := base.Facts()
		normal = watch.Normal{
			Known:      true,
			Source:     fmt.Sprintf("%s, saved %s", key, savedAt.Local().Format("2006-01-02 15:04")),
			LossPct:    f64(bf["gateway_loss_pct"]),
			RTTms:      f64(bf["gateway_rtt_avg_ms"]),
			DNSms:      f64(bf["dns_latency_ms"]),
			GatewayMAC: fmt.Sprintf("%v", bf["gateway_mac"]),
		}
	}

	w := watch.New(normal)
	fmt.Printf("netdiag %s — watch: %s at %s intervals (Ctrl-C ends early and still reports)\n",
		toolVersion, *duration, *interval)
	fmt.Println(strings.Repeat("─", 72))
	if !normal.Known {
		fmt.Println("  no baseline at this location — using absolute thresholds " +
			"(run `netdiag baseline` while healthy to sharpen this)")
	}
	fmt.Println()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	deadline := time.After(*duration)
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	var samples []watch.Sample
	alerted := false
	take := func(facts map[string]any) {
		s := watch.FromFacts(time.Now(), facts)
		samples = append(samples, s)
		for _, e := range w.Add(s) {
			if !*quiet {
				fmt.Printf("  %s  [%s] %s\n", e.At.Local().Format("15:04:05"), e.Severity, e.What)
			}
			// A watch can run for hours; nobody stares at it. The first
			// critical event rings the terminal bell and puts a banner on
			// screen, so the run can be left in a corner and still be noticed.
			if e.Severity == "critical" && !alerted {
				alerted = true
				fmt.Printf("\a\n  %s\n  ** FAULT CAUGHT at %s — %s **\n  %s\n\n",
					strings.Repeat("=", 66), e.At.Local().Format("15:04:05"), e.Kind,
					strings.Repeat("=", 66))
			}
		}
	}
	take(probeFacts) // the probe run above is sample #1 — nothing wasted

	interrupted := false
loop:
	for {
		select {
		case <-stop:
			interrupted = true
			break loop
		case <-deadline:
			break loop
		case <-ticker.C:
			snap := run.Only(collectors.ForThisOS(), watch.SampleCollectors, toolVersion)
			take(snap.Facts())
		}
	}

	fmt.Println()
	if interrupted {
		fmt.Println("  (interrupted — reporting what was captured)")
	}
	fmt.Print(w.Summary())

	if *savePath != "" || *jsonOut {
		rec := map[string]any{
			"tool_version": toolVersion, "started": samples[0].At,
			"samples": samples, "events": w.Events, "periodicity": w.Periodic(),
		}
		b, _ := json.MarshalIndent(rec, "", "  ")
		if *savePath != "" {
			if err := os.WriteFile(*savePath, b, 0o600); err != nil {
				fmt.Fprintln(os.Stderr, "save error:", err)
			}
		}
		if *jsonOut {
			fmt.Println(string(b))
		}
	}
	for _, e := range w.Events {
		if e.Severity == "critical" {
			return 1 // a caught fault is a non-zero exit, like a critical finding
		}
	}
	return 0
}

func f64(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case int:
		return float64(t)
	}
	return 0
}

// ---------------------------------------------------------------- scan (default)

func scanCmd(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "emit the snapshot + findings as JSON instead of the report")
	kbPath := fs.String("kb", "", "path to an external rules.json (default: embedded seed KB)")
	save := fs.String("save", "", "also write the snapshot JSON to this file (for future `compare`)")
	mdPath := fs.String("md", "", "also write the report as Markdown to this file ('-' for stdout)")
	htmlPath := fs.String("html", "", "also write the report as a self-contained HTML page")
	anon := fs.Bool("anon", false, "redact addresses, MACs and hostnames per the recorded policy (§4.3)")
	forUser := fs.Bool("for-user", false, "add the plain-language rendering (§6.2)")
	since := fs.Int("since", 24, "event-history window in hours")
	diff := fs.Bool("diff", false, "report drift against this location's baseline (§5.2)")
	against := fs.String("against", "", "which baseline to diff against: a number (2 = second newest), a date (2026-07-14), or an age (7d). Default: the newest")
	showVersion := fs.Bool("version", false, "print version and exit")
	_ = fs.Parse(args)

	if *showVersion {
		fmt.Println("netdiag", toolVersion)
		return 0
	}
	collectors.EventWindowHours = *since

	// A malformed -against is knowable before anything is collected. Making
	// someone sit through a full scan to be told "last tuesday" is not a date
	// wastes the one resource the tool is supposed to save.
	if *against != "" {
		if _, _, err := baseline.ParseWhen(*against); err != nil {
			fmt.Fprintln(os.Stderr, "  "+err.Error())
			return 2
		}
	}

	rules, kbSource, err := interpret.LoadRules(*kbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "kb error:", err)
		return 2
	}
	stopProgress := startProgress()
	snap := run.All(collectors.ForThisOS(), toolVersion)
	stopProgress()
	facts := snap.Facts()
	findings := interpret.Evaluate(rules, facts)
	blame := triage.Blame(facts, "")
	// Bug #25 (Zorin, 0.9.18) — bug #7's family, resurfaced.
	//
	// This amendment used to fire only on CRITICAL findings. A scan with four
	// WARNINGS therefore printed "all 3 measured segments are healthy —
	// whatever the user saw is not visible from this machine right now"
	// directly above a layer report showing L1 ✗, L3 ✗ and L7 ✗: 126 link
	// flaps, a 1380 MTU and a dead IPv6 path, every one of them visible from
	// this machine, at that moment, in the same output.
	//
	// A warning is a thing the tool CAN see. Only info-level notes are quiet
	// enough to leave the all-clear standing.
	for _, f := range findings {
		if f.Severity == "critical" || f.Severity == "warning" {
			blame.NoteUnattributed(f.Finding)
			break
		}
	}

	if *anon {
		snap.Redact()
	}
	if *save != "" {
		b, _ := json.MarshalIndent(snap, "", "  ")
		if err := os.WriteFile(*save, b, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "save error:", err)
		}
	}
	if *mdPath != "" {
		md := report.RenderMarkdown(snap, findings, kbSource, blame.Verdict)
		if *mdPath == "-" {
			fmt.Print(md)
		} else if err := os.WriteFile(*mdPath, []byte(md), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "md error:", err)
		}
	}
	if *htmlPath != "" {
		segs := make([][3]string, 0, len(blame.Segments))
		for _, sg := range blame.Segments {
			segs = append(segs, [3]string{sg.Name, string(sg.Status), sg.Evidence})
		}
		page := report.RenderHTML(snap, findings, kbSource, blame.Verdict, segs)
		if err := os.WriteFile(*htmlPath, []byte(page), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "html error:", err)
		} else {
			fmt.Printf("Report written to %s — open it in a browser.\n", *htmlPath)
		}
	}
	if *jsonOut {
		out := map[string]any{"snapshot": snap, "findings": findings, "blame": blame}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
	} else {
		fmt.Print(headline(findings, blame.Verdict))
		fmt.Print(report.Render(snap, findings, kbSource, blame.Render()))
		if *forUser {
			fmt.Print("\n" + report.RenderForUser(findings))
		}
		printNextSteps(findings)
		// Discoverability: the verbs are only obvious to whoever wrote them.
		fmt.Println("\n  Tip: run `netdiag menu` for a guided list of checks,")
		fmt.Println("       or `netdiag -html report.html` for a report you can open and share.")
	}
	// -diff: the motion detector (§5.2) — what changed at THIS location.
	if *diff {
		fmt.Println()
		printDiff(facts, *against)
	}
	return exitCode(findings)
}

// ----------------------------------------------------------------- why (§6)

func whyCmd(args []string) int {
	fs := flag.NewFlagSet("why", flag.ExitOnError)
	forUser := fs.Bool("for-user", false, "add the plain-language rendering (§6.2)")
	kbPath := fs.String("kb", "", "path to an external rules.json")
	since := fs.Int("since", 24, "event-history window in hours")
	ask := fs.Bool("ask", false, "interactive pruning: max two binary questions (v5 §7)")
	// symptom and optional target come before flags: netdiag why cant-reach host -for-user
	var symptom, target string
	rest := args
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		symptom, rest = rest[0], rest[1:]
	}
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		target, rest = rest[0], rest[1:]
	}
	_ = fs.Parse(rest)
	collectors.EventWindowHours = *since

	profiles := triage.Profiles()
	prof, known := profiles[symptom]
	if symptom == "" || !known {
		if symptom != "" {
			// Unknown symptom → full scan, same graceful degradation (§6).
			fmt.Fprintf(os.Stderr, "unknown symptom %q — falling back to a full scan.\n", symptom)
			fmt.Fprintf(os.Stderr, "known: %s\n\n", strings.Join(profileNames(profiles), ", "))
			return scanCmd(nil)
		}
		fmt.Println("usage: netdiag why <symptom> [target] [-for-user]")
		fmt.Println("symptoms:", strings.Join(profileNames(profiles), ", "))
		return 2
	}
	if needsTarget(symptom) && target == "" && symptom != "cant-login" {
		fmt.Fprintf(os.Stderr, "why %s needs a target: netdiag why %s <host[:port]>\n", symptom, symptom)
		return 2
	}

	rules, kbSource, err := interpret.LoadRules(*kbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "kb error:", err)
		return 2
	}
	// Interactive pruning (§6): one binary question, whole branch gone.
	if *ask && (symptom == "no-internet" || symptom == "slow" || symptom == "intermittent") {
		fmt.Fprint(os.Stderr, "Wired or Wi-Fi? [w=wired / f=wifi / enter=both] ")
		var answer string
		fmt.Scanln(&answer)
		switch strings.ToLower(strings.TrimSpace(answer)) {
		case "w", "wired":
			prof = prof.PruneMedium("wired")
		case "f", "wifi", "wi-fi":
			prof = prof.PruneMedium("wifi")
		}
	}
	stopProgress := startProgress()
	snap := run.All(collectors.ForThisOS(), toolVersion)
	stopProgress()
	facts := snap.Facts()
	if prof.Prepare != nil {
		fmt.Fprint(os.Stderr, "  probing the target … \r")
		prof.Prepare(facts, target) // target probes add target_* facts
	}
	findings := interpret.Evaluate(rules, facts)
	blame := triage.Blame(facts, prof.DCLabel)
	// A config/service fault above the transport path leaves every segment
	// green; the verdict must say so rather than "nothing is visible here".
	blame.NoteUnattributed(prof.FirstBreak(facts))

	fmt.Printf("netdiag v1.1 — why %s%s  (kb: %s)\n", symptom, sp(target), kbSource)
	fmt.Println(strings.Repeat("─", 72) + "\n")
	fmt.Print(blame.Render() + "\n")
	fmt.Print(prof.Walk(facts, findings))
	if *forUser {
		fmt.Print(report.RenderForUser(prune(findings, prof)))
	}
	printNotChecked(snap)
	if symptom == "slow" {
		offerLoadTest(facts, findings)
	}
	return exitCode(findings)
}

// offerLoadTest closes the honest gap in `why slow`: the passive walk can
// measure loss, latency and DNS, and the single most common real cause of
// "everything is slow" — bufferbloat — is invisible to all three. An idle link
// looks perfect right up until someone loads it.
//
// It is an OFFER, never automatic. `why slow` is part of the read-only,
// costs-nothing promise, and the load test deliberately fills the link and
// spends the user's data. Auto-running it here would break the promise the
// rest of the tool is built on, so the passive walk states what it could not
// see and lets the person decide.
func offerLoadTest(facts map[string]any, findings []interpret.Finding) {
	// If the passive walk already found something that explains slowness,
	// leading with a data-spending test would be noise. Say nothing.
	for _, f := range findings {
		if f.Severity == "critical" || f.Severity == "warning" {
			return
		}
	}

	fmt.Println()
	fmt.Println("  The checks above measure an IDLE link. They cannot see bufferbloat:")
	fmt.Println("  latency that only appears once the line is busy, which is the most")
	fmt.Println("  common cause of \"calls break up while someone uploads\" — and it")
	fmt.Println("  looks perfect on every idle test, including this one.")
	if wireless, ok := facts["link_primary_is_wireless"].(bool); ok && wireless {
		fmt.Println("  (On Wi-Fi, the radio itself is the other usual answer — `netdiag why wifi`.)")
	}
	fmt.Println()
	fmt.Println("  To measure it:  netdiag speed        (uses data — it asks first)")
}

// printDiff renders drift against the chosen baseline. Which baseline was
// used, and when it was taken, is part of the ANSWER — "nothing changed" means
// nothing without the date it is measured from.
func printDiff(facts map[string]any, against string) {
	if against == "" {
		// Unchanged path: the single current baseline, so an install that
		// predates history still works exactly as before.
		base, savedAt, _, err := baseline.Load(facts)
		if err != nil {
			offerBaseline(facts)
			return
		}
		header := fmt.Sprintf("vs the snapshot saved %s", savedAt.Local().Format("Mon 2 Jan, 15:04"))
		fmt.Print(baseline.Render(baseline.Diff(base.Facts(), facts), header))
		return
	}

	n, when, err := baseline.ParseWhen(against)
	if err != nil {
		fmt.Fprintln(os.Stderr, "  "+err.Error())
		return
	}
	var (
		base  *schema.Snapshot
		entry baseline.Entry
	)
	if n > 0 {
		base, entry, err = baseline.LoadNth(facts, n)
	} else {
		base, entry, err = baseline.LoadNearest(facts, when)
	}
	if err != nil {
		// Never fall back to a different baseline than the one asked for. A
		// diff against the wrong day, unlabelled, is worse than no diff.
		fmt.Fprintln(os.Stderr, "  "+err.Error())
		fmt.Fprintln(os.Stderr, "  `netdiag baseline -list` shows what is kept here.")
		return
	}
	header := fmt.Sprintf("vs the snapshot saved %s (%s ago)",
		entry.SavedAt.Local().Format("Mon 2 Jan, 15:04"), humanAge(entry.Age()))
	fmt.Print(baseline.Render(baseline.Diff(base.Facts(), facts), header))
}

// headline answers, in the first three lines, the question the person actually
// has: is something wrong, and do I need to read the rest?
//
// The full report is dense on purpose — it is evidence. But evidence with no
// summary makes someone scan forty lines to learn there is nothing to see, and
// that is the difference between a tool people run and a tool people mean to
// run.
func headline(findings []interpret.Finding, verdict string) string {
	var crit, warn, info int
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			crit++
		case "warning":
			warn++
		default:
			info++
		}
	}

	var b strings.Builder
	b.WriteString("\n")
	switch {
	case crit > 0 && warn > 0:
		fmt.Fprintf(&b, "  %s broken here, and %s worth a look.\n",
			count(crit, "thing is", "things are"), count(warn, "one more is", "more are"))
	case crit > 0:
		fmt.Fprintf(&b, "  %s broken here.\n", count(crit, "thing is", "things are"))
	case warn > 0:
		fmt.Fprintf(&b, "  Nothing is broken, but %s worth a look.\n",
			count(warn, "one thing is", "things are"))
	default:
		// Never "all clear": the tool only knows what it measured, and the
		// not-checked list below is part of this sentence's meaning.
		b.WriteString("  Nothing failed the checks below.\n")
	}
	// Bug #26 (Zorin, 0.9.18): the headline said "4 things are worth a look"
	// above a section headed "Findings (6)". It counted warnings and silently
	// dropped the info notes. Two numbers for one list, in one screen, is the
	// tool contradicting itself — and it teaches the reader that the summary
	// cannot be trusted, which costs more than the summary is worth.
	if info > 0 {
		fmt.Fprintf(&b, "  Plus %s worth knowing about. (%d findings in total.)\n",
			count(info, "note", "notes"), crit+warn+info)
	}
	if v := strings.TrimSpace(verdict); v != "" && crit+warn > 0 {
		fmt.Fprintf(&b, "  %s\n", capitalise(v))
	}
	b.WriteString("\n")
	return b.String()
}

// count renders "1 thing is" / "3 things are" without the "(s)" that makes
// output look generated rather than written.
func count(n int, one, many string) string {
	if n == 1 {
		if strings.HasPrefix(one, "one ") {
			return one
		}
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// printNextSteps closes the loop: a person who has just read a finding should
// not have to guess which of twenty verbs comes next.
func printNextSteps(findings []interpret.Finding) {
	var crit bool
	for _, f := range findings {
		if f.Severity == "critical" {
			crit = true
		}
	}
	fmt.Println("\n  What next:")
	if crit {
		fmt.Println("   • netdiag ticket           hand this to someone with the evidence")
		fmt.Println("   • netdiag -for-user        the same result without the jargon")
	} else {
		fmt.Println("   • netdiag baseline         remember this as healthy, to compare later")
		fmt.Println("   • netdiag why slow         if it feels slow but nothing failed here")
	}
}

func capitalise(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// offerBaseline turns a dead end into an action. "No baseline — run `netdiag
// baseline` first" tells someone their request failed and leaves them to fix
// it; asking is one keystroke and leaves them with the thing they wanted.
func offerBaseline(facts map[string]any) {
	fmt.Printf("  Nothing saved yet for %s, so there is nothing to compare with.\n\n",
		baseline.Describe(facts))

	if !isInteractive() {
		fmt.Println("  Run `netdiag baseline` here while things are working.")
		return
	}
	fmt.Print("  Save this machine's current state as the healthy snapshot? [y/N] ")
	in := bufio.NewScanner(os.Stdin)
	if !in.Scan() || !strings.HasPrefix(strings.ToLower(strings.TrimSpace(in.Text())), "y") {
		fmt.Println("  Nothing saved. Run `netdiag baseline` here when it is working well.")
		return
	}
	// Deliberately re-collect rather than reusing this run's snapshot: the
	// person is answering "is it healthy NOW", and the scan they just read is
	// the evidence they answered with.
	snap := run.All(collectors.ForThisOS(), toolVersion)
	if _, err := baseline.Save(snap, snap.Facts()); err != nil {
		fmt.Fprintln(os.Stderr, "  could not save:", err)
		return
	}
	fmt.Println("  Saved. `netdiag -diff` here will now show what changed since today.")
}

// isInteractive reports whether stdin looks like a terminal. It is not exact
// (/dev/null passes), but the prompt fails SAFE either way: an immediate EOF
// reads as "no", so an unattended run never saves a baseline by accident and
// never blocks waiting for an answer.
func isInteractive() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && (fi.Mode()&os.ModeCharDevice) != 0
}

// humanAge is "3d" / "5h" / "12m" rather than Go's "72h0m0s".
func humanAge(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
}

func prune(findings []interpret.Finding, prof triage.Profile) []interpret.Finding {
	var out []interpret.Finding
	for _, f := range findings {
		if prof.Layers[f.Layer] {
			out = append(out, f)
		}
	}
	return out
}

func printNotChecked(snap *schema.Snapshot) {
	var notRun []string
	for name, res := range snap.Collectors {
		if res.Status != schema.StatusOK {
			notRun = append(notRun, fmt.Sprintf("%s (%s: %s)", name, res.Status, res.Reason))
		}
	}
	if len(notRun) == 0 {
		return
	}
	fmt.Println("  Not checked / degraded — these are NOT green:")
	for _, n := range notRun {
		fmt.Println("   • " + n)
	}
}

func profileNames(m map[string]triage.Profile) []string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func needsTarget(symptom string) bool {
	switch symptom {
	case "cant-reach", "cant-print", "cant-rdp":
		return true
	}
	return false
}

func sp(s string) string {
	if s == "" {
		return ""
	}
	return " " + s
}

// ------------------------------------------------------------- feedback (§5.3)

func feedbackCmd(args []string) int {
	if len(args) == 0 {
		stats, err := feedback.Rollup()
		if err != nil {
			fmt.Fprintln(os.Stderr, "feedback error:", err)
			return 2
		}
		fmt.Print(feedback.Render(stats))
		return 0
	}
	if len(args) < 2 {
		fmt.Println("usage: netdiag feedback <rule-id> confirmed|wrong [--note \"...\"]")
		fmt.Println("       netdiag feedback            (show the per-rule rollup)")
		return 2
	}
	ruleID, verdict := args[0], args[1]
	note := ""
	for i := 2; i < len(args); i++ {
		if args[i] == "--note" && i+1 < len(args) {
			note = args[i+1]
		}
	}
	if err := feedback.Append(ruleID, verdict, note); err != nil {
		fmt.Fprintln(os.Stderr, "feedback error:", err)
		return 2
	}
	fmt.Printf("recorded: %s %s%s  → %s\n", ruleID, verdict, noteSuffix(note), feedback.Path())
	return 0
}

func noteSuffix(n string) string {
	if n == "" {
		return ""
	}
	return " (with note)"
}

func exitCode(findings []interpret.Finding) int {
	for _, f := range findings {
		if f.Severity == "critical" {
			return 1
		}
	}
	return 0
}
