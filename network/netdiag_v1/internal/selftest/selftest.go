// Package selftest answers one question on the customer's machine, in
// seconds, with no network: does THIS binary still reason correctly?
//
// Unit tests prove the build was good on the machine that compiled it. This
// proves the build in front of you is good — after a USB copy, after an
// antivirus quarantine-and-restore, after a field tech hand-edited kb.json to
// add a rule at 2am. It drives the REAL rules engine, the REAL blame logic and
// the REAL renderer with fixed facts, and checks the sentences that come out.
//
// Every scenario here is a property the tool has already been caught getting
// wrong in the field. The suite is not a demo; it is the list of lies this
// tool has told, frozen so it cannot tell them again.
package selftest

import (
	"fmt"
	"sort"
	"strings"

	"netdiag/internal/interpret"
	"netdiag/internal/schema"
	"netdiag/internal/triage"
)

// Scenario is a fact set with the verdict it must produce.
type Scenario struct {
	Name   string
	Guards string // the field bug or promise this exists to protect

	Facts   map[string]any
	DCLabel string

	MustFire    []string // rule IDs that have to fire on these facts
	MustNotFire []string // rule IDs that must NOT fire — false positives are bugs too

	VerdictHas    []string // substrings the rendered verdict must contain
	VerdictLacks  []string // substrings it must not contain
	MinSeverities map[string]int
}

// Result is one scenario's outcome. Failures are sentences, not codes: the
// person reading this output is deciding whether to trust the tool.
type Result struct {
	Name     string
	Guards   string
	Pass     bool
	Failures []string
}

// Run executes the integrity checks and every scenario against the given KB
// (empty path = the embedded one). It never touches the network, reads no
// system state, and changes nothing.
func Run(kbPath string) []Result {
	var out []Result

	rules, source, err := interpret.LoadRules(kbPath)
	if err != nil {
		return []Result{{
			Name: "knowledge base loads", Pass: false,
			Guards:   "a corrupt or truncated KB must fail loudly, not run with fewer rules",
			Failures: []string{fmt.Sprintf("could not load %s: %v", displaySource(kbPath), err)},
		}}
	}

	out = append(out, integrity(rules, source)...)
	for _, sc := range Scenarios() {
		out = append(out, sc.run(rules))
	}
	out = append(out, profileCheck())
	return out
}

// Passed reports whether every result passed, and how many did not.
func Passed(results []Result) (ok bool, failed int) {
	for _, r := range results {
		if !r.Pass {
			failed++
		}
	}
	return failed == 0, failed
}

// ---------------------------------------------------------------- integrity

// integrity checks the knowledge base itself. This matters most for a KB the
// tech edited on site: a rule with no next step is trivia, a rule with no
// for_user text breaks --for-user silently, and a duplicate id makes feedback
// ambiguous.
func integrity(rules []interpret.Rule, source string) []Result {
	load := Result{
		Name:   "knowledge base loads",
		Guards: "a corrupt or truncated KB must fail loudly, not run with fewer rules",
		Pass:   true,
	}
	if len(rules) == 0 {
		load.Pass = false
		load.Failures = append(load.Failures, "loaded zero rules — the tool would report every machine as healthy")
	}
	load.Failures = append(load.Failures, fmt.Sprintf("· %d rules from %s", len(rules), source))

	shape := Result{
		Name:   "every rule is actionable",
		Guards: "a finding with no next step is trivia; one with no plain-language text breaks --for-user",
		Pass:   true,
	}
	seen := map[string]bool{}
	validLayer := map[string]bool{"L1": true, "L2": true, "L3": true, "L4": true, "L5": true, "L6": true, "L7": true}
	validSev := map[string]bool{"info": true, "warning": true, "critical": true}

	for _, r := range rules {
		switch {
		case r.ID == "":
			shape.Failures = append(shape.Failures, "a rule has no id — feedback could never name it")
		case seen[r.ID]:
			shape.Failures = append(shape.Failures, fmt.Sprintf("duplicate rule id %q", r.ID))
		}
		seen[r.ID] = true

		if !validLayer[r.Layer] {
			shape.Failures = append(shape.Failures, fmt.Sprintf("%s: layer %q is not L1–L7", r.ID, r.Layer))
		}
		if !validSev[r.Severity] {
			shape.Failures = append(shape.Failures, fmt.Sprintf("%s: severity %q is not info/warning/critical", r.ID, r.Severity))
		}
		if strings.TrimSpace(r.Finding) == "" {
			shape.Failures = append(shape.Failures, r.ID+": no finding text")
		}
		if strings.TrimSpace(r.NextStep) == "" {
			shape.Failures = append(shape.Failures, r.ID+": no next step — a finding without a remedy is trivia")
		}
		if strings.TrimSpace(r.ForUser) == "" {
			shape.Failures = append(shape.Failures, r.ID+": no for_user text — --for-user would drop it silently")
		}
		if len(r.Match) == 0 {
			shape.Failures = append(shape.Failures, r.ID+": matches nothing, so it can never fire")
		}
	}
	shape.Pass = len(shape.Failures) == 0

	// Every fact a rule reads must have a redaction classification, or a
	// --redact report leaks it. The unit test enforces this for the embedded
	// KB; here it also covers a KB written on site.
	priv := Result{
		Name:   "no rule reads an unclassified fact",
		Guards: "an unclassified fact survives --redact — the promise that a report is safe to email",
		Pass:   true,
	}
	var unclassified []string
	for _, r := range rules {
		for key := range r.Match {
			// Resolve the key the way the ENGINE does, not the way it looks:
			// "gateway_loss_pct_above" reads the fact "gateway_loss_pct".
			fact, _ := interpret.FactKey(key)
			if _, known := schema.RedactionPolicy[fact]; !known {
				unclassified = append(unclassified, fmt.Sprintf("%s reads %q", r.ID, fact))
			}
		}
	}
	sort.Strings(unclassified)
	priv.Failures = unclassified
	priv.Pass = len(unclassified) == 0

	return []Result{load, shape, priv}
}

// profileCheck validates the symptom walks: a check that names a fact nobody
// classifies, or a profile with no checks, means a `why` verb that quietly
// walks past the fault.
func profileCheck() Result {
	res := Result{
		Name:   "every symptom walk is wired",
		Guards: "a `why` verb with an empty or unclassified walk reports a clean run on a broken machine",
		Pass:   true,
	}
	profiles := triage.Profiles()
	if len(profiles) == 0 {
		res.Pass = false
		res.Failures = []string{"no symptom profiles registered — every `why` verb is dead"}
		return res
	}
	names := make([]string, 0, len(profiles))
	for name := range profiles {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		p := profiles[name]
		if len(p.Checks) == 0 {
			res.Failures = append(res.Failures, fmt.Sprintf("%q has no checks", name))
			continue
		}
		for _, c := range p.Checks {
			if strings.TrimSpace(c.What) == "" {
				res.Failures = append(res.Failures, fmt.Sprintf("%q has a check with no description", name))
			}
		}
	}
	res.Pass = len(res.Failures) == 0
	if res.Pass {
		res.Failures = []string{fmt.Sprintf("· %d symptom walks", len(profiles))}
	}
	return res
}

// ---------------------------------------------------------------- scenarios

func (sc Scenario) run(rules []interpret.Rule) Result {
	res := Result{Name: sc.Name, Guards: sc.Guards, Pass: true}

	findings := interpret.Evaluate(rules, sc.Facts)
	fired := map[string]bool{}
	worst := map[string]int{}
	for _, f := range findings {
		fired[f.ID] = true
		worst[f.Severity]++
	}

	for _, id := range sc.MustFire {
		if !fired[id] {
			res.Failures = append(res.Failures, fmt.Sprintf("rule %s did not fire on facts that require it", id))
		}
	}
	for _, id := range sc.MustNotFire {
		if fired[id] {
			res.Failures = append(res.Failures, fmt.Sprintf("rule %s fired on facts that must not trigger it (false positive)", id))
		}
	}
	for sev, want := range sc.MinSeverities {
		if worst[sev] < want {
			res.Failures = append(res.Failures,
				fmt.Sprintf("expected at least %d %s finding(s), got %d", want, sev, worst[sev]))
		}
	}

	// The same amendment the scan path applies. Kept in step with it
	// deliberately: this harness exists to catch the scan path lying, and a
	// harness that models an older version of that path cannot.
	//
	// Bug #25 widened it from critical-only to critical-or-warning — a warning
	// is something the tool CAN see, so it cannot coexist with "not visible
	// from this machine right now".
	blame := triage.Blame(sc.Facts, sc.DCLabel)
	for _, f := range findings {
		if f.Severity == "critical" || f.Severity == "warning" {
			blame.NoteUnattributed(f.Finding)
			break
		}
	}
	verdict := blame.Render()

	for _, want := range sc.VerdictHas {
		if !strings.Contains(verdict, want) {
			res.Failures = append(res.Failures, fmt.Sprintf("verdict is missing %q", want))
		}
	}
	for _, bad := range sc.VerdictLacks {
		if strings.Contains(verdict, bad) {
			res.Failures = append(res.Failures, fmt.Sprintf("verdict wrongly claims %q", bad))
		}
	}

	res.Pass = len(res.Failures) == 0
	return res
}

// Scenarios is the frozen list. Each entry names the run that earned it.
func Scenarios() []Scenario {
	return []Scenario{
		{
			Name:   "a healthy machine is not given a fault",
			Guards: "a tool that invents problems to look useful is worse than no tool",
			Facts: map[string]any{
				"link_up": true, "gateway_reachable": true, "upstream_reachable": true,
				"gateway_loss_pct": 0, "dns_resolution_ok": true, "default_route_present": true,
			},
			VerdictHas: []string{"measured segments are healthy"},
			// …but the all-clear stays qualified. Absence of a fault now is
			// not proof of health, and the wording must keep saying so.
			VerdictLacks: []string{"everything is fine", "no problems"},
		},
		{
			Name:       "nothing measured blames nobody",
			Guards:     "guessing from no data is the failure mode that destroys trust",
			Facts:      map[string]any{},
			VerdictHas: []string{"nothing could be measured"},
			VerdictLacks: []string{
				"the problem is this machine",
				"the problem is inside your LAN",
				"the problem is past your gateway",
			},
		},
		{
			Name:   "a dead gateway is not blamed on the ISP",
			Guards: "field run: a broken LAN makes everything beyond it unknowable, not innocent",
			Facts: map[string]any{
				"link_up": true, "gateway_reachable": false, "upstream_reachable": false,
			},
			VerdictHas:   []string{"inside your LAN"},
			VerdictLacks: []string{"past your gateway"},
		},
		{
			Name:   "a down link is not graded as slow",
			Guards: "field run: the tool must refuse to grade a link that carried nothing",
			Facts: map[string]any{
				"link_up": false, "gateway_reachable": false,
			},
			VerdictLacks: []string{"past your gateway", "measured segments are healthy"},
		},
		{
			Name:   "bug #7 (AD lab, 0.5.4): a critical finding cannot sit under an all-clear",
			Guards: "every transport segment measured healthy while the machine could never find its DC",
			Facts: map[string]any{
				"link_up": true, "gateway_reachable": true, "upstream_reachable": true,
				"dns_public_resolver_only": true, "ad_srv_resolved": false,
			},
			MustFire:      []string{"ad_dns_public_resolver"},
			MinSeverities: map[string]int{"critical": 1},
			VerdictLacks:  []string{"not visible from this machine right now"},
			VerdictHas:    []string{"not the whole picture"},
		},
		{
			Name:   "bug #10 (DC, 0.7.x): an unverifiable secure channel is not reported as broken trust",
			Guards: "clock skew made the verify fail, and the tool told the user to reset a healthy machine account",
			Facts: map[string]any{
				"link_up": true, "gateway_reachable": true, "upstream_reachable": true,
				// the verify did not come back clean, but it also could not be
				// trusted — "failed to prove" is not "proved broken"
				"ad_secure_channel_ok": false, "ad_secure_channel_verifiable": false,
			},
			MustNotFire: []string{"ad_secure_channel_broken"},
		},
		{
			Name:   "…and a channel that IS verifiably broken still fires",
			Guards: "the fix for bug #10 must not have muted the real fault as well",
			Facts: map[string]any{
				"link_up": true, "gateway_reachable": true, "upstream_reachable": true,
				"ad_secure_channel_ok": false, "ad_secure_channel_verifiable": true,
			},
			MustFire: []string{"ad_secure_channel_broken"},
		},
		{
			Name:   "a slow Wi-Fi link is not diagnosed as a damaged cable",
			Guards: "L2 (0.9.14): 65 Mbps is a bad cable on copper and an ordinary afternoon on Wi-Fi",
			Facts: map[string]any{
				"link_up": true, "link_primary_is_wireless": true,
				"link_medium_confirmed": true, "link_speed_mbps": 65,
				"gateway_reachable": true, "upstream_reachable": true,
			},
			MustNotFire: []string{"link_negotiated_low_wired"},
		},
		{
			Name:   "…but a wired link at 10 Mbps still is",
			Guards: "the medium guard must not have muted the fault it was added to qualify",
			Facts: map[string]any{
				"link_up": true, "link_primary_is_wireless": false,
				"link_medium_confirmed": true, "link_speed_mbps": 10,
				"gateway_reachable": true, "upstream_reachable": true,
			},
			MustFire: []string{"link_negotiated_low_wired"},
		},
		{
			Name:   "a gigabit wired link is left alone",
			Guards: "the speed rule must not fire on a healthy link",
			Facts: map[string]any{
				"link_up": true, "link_primary_is_wireless": false,
				"link_medium_confirmed": true, "link_speed_mbps": 1000,
				"link_duplex": "full", "gateway_reachable": true, "upstream_reachable": true,
			},
			MustNotFire: []string{"link_negotiated_low_wired", "duplex_mismatch"},
		},
		{
			Name:   "802.1X: a held port is not reported as a rejected credential",
			Guards: "L2 (0.9.14): 'no answer from RADIUS' and 'RADIUS said no' need different next steps",
			Facts: map[string]any{
				"link_up": true, "dot1x_active": true, "dot1x_port_status": "Unauthorized",
				"dot1x_eap_state": "HELD",
			},
			MustFire:    []string{"dot1x_port_unauthorized"},
			MustNotFire: []string{"dot1x_auth_failed"},
		},
		{
			Name:   "a machine with no wireless does not get Wi-Fi findings",
			Guards: "absent is not open — a missing key must never read as an insecure value",
			Facts: map[string]any{
				"link_up": true, "link_primary_is_wireless": false,
				"gateway_reachable": true, "upstream_reachable": true,
			},
			MustNotFire: []string{"wifi_open_network"},
		},
		{
			Name:   "bug #25 (Zorin, 0.9.18): warnings also outrank an all-clear headline",
			Guards: "a scan with 4 warnings printed 'not visible from this machine right now' above L1 ✗, L3 ✗ and L7 ✗",
			Facts: map[string]any{
				// every transport segment genuinely healthy…
				"link_up": true, "gateway_reachable": true, "upstream_reachable": true,
				"gateway_loss_pct": 0, "upstream_loss_pct": 0,
				// …and a warning that is plainly visible from right here
				"ipv6_global_present": true, "ipv6_path_ok": false,
			},
			MustFire:     []string{"ipv6_broken_dualstack"},
			VerdictLacks: []string{"not visible from this machine right now"},
			VerdictHas:   []string{"not the whole picture"},
		},
		{
			Name:   "bug #30 (Zorin Wi-Fi, 0.9.20): link flaps do not send a laptop user to check a cable",
			Guards: "`why wifi` on a Wi-Fi-only laptop advised 'check cable and switch port' for 21 wireless disconnects",
			Facts: map[string]any{
				"link_up": true, "link_primary_is_wireless": true, "link_medium_confirmed": true,
				"link_flaps_24h": 21, "link_flaps_attributed": true,
				"gateway_reachable": true, "upstream_reachable": true,
			},
			MustFire: []string{"link_flap_history"},
		},
		{
			Name:   "bug #31 (Zorin, 0.9.22): an unplugged port's flaps are not this machine's link dropping",
			Guards: "46 flaps of an idle ethernet port were reported as 'the link went down repeatedly' on a laptop working over Wi-Fi",
			Facts: map[string]any{
				"link_up": true, "gateway_reachable": true, "upstream_reachable": true,
				"link_flaps_24h": 0, "link_flaps_attributed": true,
				"link_flaps_other_total": 46,
			},
			MustNotFire: []string{"link_flap_history"},
			MustFire:    []string{"idle_iface_flapping"},
		},
		{
			Name:   "an UNCONFIRMED medium blocks the cable verdict entirely",
			Guards: "Windows reads the medium from a struct offset never watched execute; if it is wrong it reads 'wired' on every machine, including Wi-Fi laptops",
			Facts: map[string]any{
				"link_up": true, "link_primary_is_wireless": false,
				"link_medium_confirmed": false, "link_speed_mbps": 10,
				"gateway_reachable": true, "upstream_reachable": true,
			},
			MustNotFire: []string{"link_negotiated_low_wired"},
		},
		{
			Name:   "a non-domain machine gets no DC segment",
			Guards: "a home laptop's report must not be cluttered with AD it does not have",
			Facts: map[string]any{
				"link_up": true, "gateway_reachable": true, "upstream_reachable": true,
			},
			VerdictLacks: []string{"DC / domain"},
		},
		{
			Name:    "a domain run keeps its DC segment",
			Guards:  "the fourth segment is the whole point of `why cant-login`",
			DCLabel: "DC / domain",
			Facts: map[string]any{
				"link_up": true, "gateway_reachable": true, "upstream_reachable": true,
				// the 4th segment exists only once a destination was actually
				// probed — without target_name there is nothing to report on
				"target_name":    "dc01.corp.local",
				"target_ping_ok": true, "target_port_state": "open",
			},
			VerdictHas: []string{"DC / domain"},
		},
	}
}

// Render formats results for a terminal. Failures print their sentences; the
// summary line is what a tech screenshots.
func Render(results []Result, toolVersion string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "netdiag %s — selftest\n", toolVersion)
	b.WriteString(strings.Repeat("─", 72) + "\n")
	b.WriteString("\n  No network, no system state, nothing changed: fixed facts through\n")
	b.WriteString("  the real rules, the real blame logic and the real renderer.\n\n")

	for _, r := range results {
		mark := "PASS"
		if !r.Pass {
			mark = "FAIL"
		}
		fmt.Fprintf(&b, "  [%s] %s\n", mark, r.Name)
		for _, f := range r.Failures {
			if strings.HasPrefix(f, "·") { // informational, not a failure
				fmt.Fprintf(&b, "         %s\n", f)
				continue
			}
			fmt.Fprintf(&b, "         %s\n", f)
		}
		if !r.Pass && r.Guards != "" {
			fmt.Fprintf(&b, "         guards: %s\n", r.Guards)
		}
	}

	ok, failed := Passed(results)
	b.WriteString("\n" + strings.Repeat("─", 72) + "\n")
	if ok {
		fmt.Fprintf(&b, "  %d/%d passed. This build reasons correctly.\n", len(results), len(results))
		b.WriteString("  (It says nothing about the network — run `netdiag` for that.)\n")
	} else {
		fmt.Fprintf(&b, "  %d of %d checks FAILED. Do not trust this build's verdicts.\n", failed, len(results))
		b.WriteString("  Re-copy the binary, or restore the knowledge base it shipped with.\n")
	}
	return b.String()
}

func displaySource(kbPath string) string {
	if kbPath == "" {
		return "the embedded knowledge base"
	}
	return kbPath
}
