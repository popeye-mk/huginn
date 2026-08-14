// Package interpret is the rules engine (spec §5): string/threshold
// if-this-then-that matching, no ML, every finding carrying an OSI layer.
// v0 note: rules ship as embedded JSON so the binary has zero external
// dependencies; the YAML front-end lands with the first module dependency.
package interpret

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

//go:embed rules.json
var embeddedRules []byte

// Rule mirrors the KB entry shape from spec §5. From v1, every entry carries
// a repro tag (§16.1): "namespace"/"netem" (scripted in test/faults.sh) or
// "hardware-only" (real gear; KVM/physical lab list). Enforced by unit test
// for the embedded KB; external KBs get a pass so field techs can hand-write
// rules on site.
type Rule struct {
	ID         string         `json:"id"`
	Layer      string         `json:"layer"` // L1..L7
	Severity   string         `json:"severity"`
	Confidence string         `json:"confidence"`
	Finding    string         `json:"finding"`
	NextStep   string         `json:"next_step,omitempty"`
	Repro      string         `json:"repro,omitempty"`
	ForUser    string         `json:"for_user,omitempty"` // §6.2: same finding, jargon-free
	Match      map[string]any `json:"match"`
}

// Finding is a fired rule.
type Finding struct {
	Rule
	Evidence map[string]any `json:"evidence"`
}

// LoadRules prefers an external KB next to the binary (portable USB-stick
// story, spec §17.2) and falls back to the embedded seed rules.
func LoadRules(externalPath string) ([]Rule, string, error) {
	if externalPath != "" {
		b, err := os.ReadFile(externalPath)
		if err != nil {
			return nil, "", fmt.Errorf("kb file: %w", err)
		}
		r, err := parseRules(b)
		return r, externalPath, err
	}
	r, err := parseRules(embeddedRules)
	return r, "embedded", err
}

func parseRules(b []byte) ([]Rule, error) {
	var rules []Rule
	if err := json.Unmarshal(b, &rules); err != nil {
		return nil, err
	}
	for _, r := range rules {
		if r.ID == "" || r.Layer == "" || len(r.Match) == 0 {
			return nil, fmt.Errorf("rule %q: id, layer and match are mandatory", r.ID)
		}
	}
	return rules, nil
}

// Evaluate fires every rule whose conditions ALL hold against the facts.
// Condition semantics (spec §5 examples):
//
//	key: value          equality (bool/string/number)
//	key_above: N        numeric fact "key" > N
//	key_below: N        numeric fact "key" < N
//
// A condition on a fact that is absent NEVER matches — a rule cannot fire
// on unmeasured data (the interpreter-side "absence is never health").
func Evaluate(rules []Rule, facts map[string]any) []Finding {
	var out []Finding
	for _, r := range rules {
		ev := map[string]any{}
		ok := true
		for key, want := range r.Match {
			factKey, cmp := FactKey(key)
			got, present := facts[factKey]
			if !present || !compare(cmp, got, want) {
				ok = false
				break
			}
			ev[factKey] = got
		}
		if ok {
			out = append(out, Finding{Rule: r, Evidence: ev})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return sevRank(out[i].Severity) > sevRank(out[j].Severity)
	})
	return out
}

// FactKey maps a rule's match key to the fact it reads, and the comparison it
// implies: "gateway_loss_pct_above" reads the fact "gateway_loss_pct" with
// "gt". Exported because anything auditing the KB — the redaction check, the
// selftest — has to resolve keys EXACTLY as the engine does. Two copies of
// this rule would drift, and the drift would be silent.
func FactKey(matchKey string) (fact, cmp string) {
	switch {
	case strings.HasSuffix(matchKey, "_above"):
		return strings.TrimSuffix(matchKey, "_above"), "gt"
	case strings.HasSuffix(matchKey, "_below"):
		return strings.TrimSuffix(matchKey, "_below"), "lt"
	}
	return matchKey, "eq"
}

func compare(cmp string, got, want any) bool {
	switch cmp {
	case "gt", "lt":
		g, gok := toFloat(got)
		w, wok := toFloat(want)
		if !gok || !wok {
			return false
		}
		if cmp == "gt" {
			return g > w
		}
		return g < w
	default:
		if gf, ok := toFloat(got); ok {
			if wf, ok2 := toFloat(want); ok2 {
				return gf == wf
			}
		}
		return fmt.Sprintf("%v", got) == fmt.Sprintf("%v", want)
	}
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case float64:
		return n, true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

func sevRank(s string) int {
	switch s {
	case "critical":
		return 3
	case "warning":
		return 2
	case "info":
		return 1
	}
	return 0
}
