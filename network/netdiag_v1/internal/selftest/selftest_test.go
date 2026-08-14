package selftest

import (
	"strings"
	"testing"

	"netdiag/internal/interpret"
)

// The suite has to pass against the shipped KB. If this test fails, either a
// rule changed meaning or the tool regressed — both need a human.
func TestShippedBuildPassesItsOwnSelftest(t *testing.T) {
	results := Run("")
	ok, failed := Passed(results)
	if !ok {
		t.Errorf("%d checks failed:\n%s", failed, Render(results, "test"))
	}
	if len(results) < 10 {
		t.Errorf("only %d checks — the suite is meant to cover every field bug", len(results))
	}
}

// A selftest that cannot fail is decoration. This proves the harness actually
// detects a wrong verdict rather than always printing PASS.
func TestTheSuiteCanActuallyFail(t *testing.T) {
	bad := Scenario{
		Name:  "deliberately impossible",
		Facts: map[string]any{"link_up": true, "gateway_reachable": true, "upstream_reachable": true},
		// This rule cannot fire on healthy facts, so the scenario must fail.
		MustFire:   []string{"ad_dns_public_resolver"},
		VerdictHas: []string{"a sentence the renderer will never produce"},
	}
	rules, _, err := interpret.LoadRules("")
	if err != nil {
		t.Fatal(err)
	}
	res := bad.run(rules)
	if res.Pass {
		t.Fatal("an impossible scenario reported PASS — the harness does not check anything")
	}
	if len(res.Failures) < 2 {
		t.Errorf("expected both the rule and the verdict failure, got %v", res.Failures)
	}
}

// Every scenario must say what it guards, so a future maintainer knows what
// they are about to delete.
func TestEveryScenarioNamesWhatItGuards(t *testing.T) {
	for _, sc := range Scenarios() {
		if strings.TrimSpace(sc.Guards) == "" {
			t.Errorf("scenario %q does not say why it exists", sc.Name)
		}
		if strings.TrimSpace(sc.Name) == "" {
			t.Error("a scenario has no name")
		}
		// A scenario that asserts nothing passes trivially and is worse than
		// no scenario, because it inflates the pass count.
		if len(sc.MustFire)+len(sc.MustNotFire)+len(sc.VerdictHas)+
			len(sc.VerdictLacks)+len(sc.MinSeverities) == 0 {
			t.Errorf("scenario %q asserts nothing", sc.Name)
		}
	}
}

// A broken KB must fail loudly. This is the USB-copy / hand-edited-rules case
// the verb exists for.
func TestMissingKBFailsLoudly(t *testing.T) {
	results := Run("/nonexistent/kb.json")
	if ok, _ := Passed(results); ok {
		t.Fatal("a missing knowledge base reported PASS")
	}
	out := Render(results, "test")
	if !strings.Contains(out, "Do not trust this build") {
		t.Errorf("the failure summary does not tell the user what to do:\n%s", out)
	}
}

// The summary line is what gets screenshotted into a ticket; it must not
// over-claim. Passing the selftest says nothing about the network.
func TestPassSummaryDoesNotClaimTheNetworkIsFine(t *testing.T) {
	out := Render(Run(""), "test")
	if !strings.Contains(out, "says nothing about the network") {
		t.Error("the pass summary lost its qualifier and now reads like a clean network result")
	}
}
