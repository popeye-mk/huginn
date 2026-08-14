// Package feedback implements the §5.3 verb: one command at ticket-closure
// time, appended to a plain local file — no cloud, no telemetry, nothing in
// the background. This is the only data source that can make the KB honest.
package feedback

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Entry is one appended line.
type Entry struct {
	At      time.Time `json:"at"`
	RuleID  string    `json:"rule_id"`
	Verdict string    `json:"verdict"` // confirmed | wrong
	Note    string    `json:"note,omitempty"`
}

// Path: next to the KB / in the user's home (spec: "stored locally next to
// the KB"); overridable for tests and USB-stick runs.
func Path() string {
	if p := os.Getenv("NETDIAG_FEEDBACK"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "netdiag_feedback.jsonl"
	}
	return filepath.Join(home, ".netdiag", "feedback.jsonl")
}

// Append records one verdict.
func Append(ruleID, verdict, note string) error {
	if verdict != "confirmed" && verdict != "wrong" {
		return fmt.Errorf("verdict must be confirmed or wrong, got %q", verdict)
	}
	p := Path()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil && filepath.Dir(p) != "." {
		return err
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	b, _ := json.Marshal(Entry{At: time.Now().UTC(), RuleID: ruleID, Verdict: verdict, Note: note})
	_, err = f.Write(append(b, '\n'))
	return err
}

// Stats is the per-rule confirmed/wrong rollup.
type Stats struct {
	Confirmed, Wrong int
	Notes            []string
}

// Rollup reads the file and aggregates. A rule whose false-positive rate
// climbs is a threshold-tuning candidate — with evidence, not opinion.
func Rollup() (map[string]*Stats, error) {
	f, err := os.Open(Path())
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]*Stats{}, nil
		}
		return nil, err
	}
	defer f.Close()
	out := map[string]*Stats{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e Entry
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue // a corrupt line never breaks the rollup
		}
		s := out[e.RuleID]
		if s == nil {
			s = &Stats{}
			out[e.RuleID] = s
		}
		if e.Verdict == "confirmed" {
			s.Confirmed++
		} else {
			s.Wrong++
		}
		if e.Note != "" {
			s.Notes = append(s.Notes, e.Note)
		}
	}
	return out, sc.Err()
}

// Render prints the rollup.
func Render(stats map[string]*Stats) string {
	if len(stats) == 0 {
		return "  No feedback recorded yet. After closing a ticket:\n" +
			"    netdiag feedback <rule-id> confirmed\n" +
			"    netdiag feedback <rule-id> wrong --note \"why it was wrong\"\n"
	}
	ids := make([]string, 0, len(stats))
	for id := range stats {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var b strings.Builder
	b.WriteString("  Per-rule feedback (local, append-only — nothing leaves this machine)\n\n")
	for _, id := range ids {
		s := stats[id]
		total := s.Confirmed + s.Wrong
		fmt.Fprintf(&b, "  %-26s %d confirmed / %d wrong", id, s.Confirmed, s.Wrong)
		if s.Wrong*2 > total {
			b.WriteString("   ← false-positive rate >50%: demote confidence or tune threshold")
		}
		b.WriteString("\n")
		for _, n := range s.Notes {
			fmt.Fprintf(&b, "      note: %s\n", n)
		}
	}
	fmt.Fprintf(&b, "\n  file: %s\n", Path())
	return b.String()
}
