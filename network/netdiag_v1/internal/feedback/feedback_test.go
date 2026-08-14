package feedback

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppendAndRollup(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NETDIAG_FEEDBACK", filepath.Join(dir, "fb.jsonl"))

	must(t, Append("gateway_lossy", "confirmed", ""))
	must(t, Append("gateway_lossy", "wrong", "legit second DHCP: failover pair"))
	must(t, Append("gateway_lossy", "wrong", ""))
	must(t, Append("link_down", "confirmed", ""))

	if err := Append("x", "maybe", ""); err == nil {
		t.Error("invalid verdict accepted")
	}

	stats, err := Rollup()
	if err != nil {
		t.Fatal(err)
	}
	gl := stats["gateway_lossy"]
	if gl == nil || gl.Confirmed != 1 || gl.Wrong != 2 || len(gl.Notes) != 1 {
		t.Errorf("gateway_lossy rollup wrong: %+v", gl)
	}
	out := Render(stats)
	if !strings.Contains(out, "false-positive rate >50%") {
		t.Error("high-FP flag missing from render")
	}
	if !strings.Contains(out, "failover pair") {
		t.Error("note missing from render")
	}
}

func TestRollupSurvivesCorruptLines(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "fb.jsonl")
	t.Setenv("NETDIAG_FEEDBACK", p)
	must(t, Append("r1", "confirmed", ""))
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString("{corrupt\n")
	f.Close()
	must(t, Append("r1", "wrong", ""))
	stats, err := Rollup()
	if err != nil {
		t.Fatal(err)
	}
	if s := stats["r1"]; s == nil || s.Confirmed != 1 || s.Wrong != 1 {
		t.Errorf("rollup after corrupt line: %+v", stats["r1"])
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
