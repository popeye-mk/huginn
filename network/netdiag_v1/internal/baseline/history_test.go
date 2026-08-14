package baseline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netdiag/internal/schema"
)

// A dated diff is only worth anything if the date is right and the baseline it
// picked is the one the user asked for. Everything below defends that.

func withHome(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
}

func snapWith(facts map[string]any) *schema.Snapshot {
	return &schema.Snapshot{
		SchemaVersion: schema.SchemaVersion, Tool: "netdiag", ToolVersion: "test",
		CollectedAt: time.Now(), Hostname: "h", OS: "linux",
		Collectors: map[string]schema.CollectorResult{
			"link": {Status: schema.StatusOK, Data: facts},
		},
	}
}

// writeAt plants a baseline with a chosen timestamp, which is the only way to
// test "since Tuesday" without waiting until Tuesday.
func writeAt(t *testing.T, key string, when time.Time, facts map[string]any) {
	t.Helper()
	dir := historyDir(key)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	b, err := json.MarshalIndent(stored{when.UTC(), key, snapWith(facts)}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	name := when.UTC().Format("20060102T150405Z") + ".json"
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The headline feature: compare against a specific older baseline.
func TestDiffAgainstAnOlderBaselinePicksThatOne(t *testing.T) {
	withHome(t)
	facts := map[string]any{"gateway_ip": "192.168.1.1"}
	key := LocationKey(facts) // history lives under the same key Save() uses
	now := time.Now()
	writeAt(t, key, now.Add(-72*time.Hour), map[string]any{"link_mtu": 1500})
	writeAt(t, key, now.Add(-24*time.Hour), map[string]any{"link_mtu": 1400})
	writeAt(t, key, now.Add(-1*time.Hour), map[string]any{"link_mtu": 1380})

	// #1 is newest, #3 the oldest.
	for _, tc := range []struct{ n, mtu int }{{1, 1380}, {2, 1400}, {3, 1500}} {
		snap, entry, err := LoadNth(facts, tc.n)
		if err != nil {
			t.Fatalf("#%d: %v", tc.n, err)
		}
		if got := snap.Facts()["link_mtu"]; got != float64(tc.mtu) {
			t.Errorf("#%d loaded mtu %v, want %d — wrong baseline selected", tc.n, got, tc.mtu)
		}
		if entry.SavedAt.IsZero() {
			t.Errorf("#%d has no date — a diff whose baseline is undated is not auditable", tc.n)
		}
	}
}

// "What did it look like on Tuesday" must never be answered with Thursday's
// data. Silently substituting a newer baseline would invert the meaning of
// every line of the diff.
func TestNearestNeverReturnsANewerBaseline(t *testing.T) {
	withHome(t)
	facts := map[string]any{}
	now := time.Now()
	writeAt(t, "unknown-location", now.Add(-48*time.Hour), map[string]any{"link_mtu": 1500})
	writeAt(t, "unknown-location", now.Add(-1*time.Hour), map[string]any{"link_mtu": 1380})

	_, entry, err := LoadNearest(facts, now.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if entry.SavedAt.After(now.Add(-24 * time.Hour)) {
		t.Errorf("returned a baseline from %s, which is AFTER the requested time", entry.SavedAt)
	}
}

// Asking for a time before any baseline exists must fail loudly and say what
// IS available, rather than quietly using the oldest one.
func TestTooOldARequestFailsAndSaysWhatExists(t *testing.T) {
	withHome(t)
	writeAt(t, "unknown-location", time.Now().Add(-2*time.Hour), map[string]any{"link_mtu": 1500})

	_, _, err := LoadNearest(map[string]any{}, time.Now().Add(-365*24*time.Hour))
	if err == nil {
		t.Fatal("silently used a baseline from after the requested date")
	}
	if !strings.Contains(err.Error(), "oldest kept here") {
		t.Errorf("error does not tell the user what IS available: %v", err)
	}
}

// Ten by default, and the OLDEST go — keeping the newest is what makes "since
// last week" possible at all.
func TestPruneKeepsTheNewest(t *testing.T) {
	withHome(t)
	key := "unknown-location"
	for i := 0; i < 15; i++ {
		writeAt(t, key, time.Now().Add(-time.Duration(i)*time.Hour), map[string]any{"n": i})
	}
	if err := prune(historyDir(key), DefaultKeep); err != nil {
		t.Fatal(err)
	}
	entries, err := listDir(historyDir(key))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != DefaultKeep {
		t.Fatalf("kept %d, want %d", len(entries), DefaultKeep)
	}
	// The survivors must be the ten most recent, in order.
	for i := 1; i < len(entries); i++ {
		if entries[i].SavedAt.After(entries[i-1].SavedAt) {
			t.Fatal("history is not newest-first")
		}
	}
	if time.Since(entries[len(entries)-1].SavedAt) > 10*time.Hour {
		t.Error("pruning dropped recent baselines and kept old ones")
	}
}

// The date comes from the file CONTENTS, never the filesystem. Copied or
// restored directories carry mtimes that lie, and a baseline dated wrongly is
// compared against the wrong day without saying so.
func TestTimestampsComeFromContentsNotFileMtime(t *testing.T) {
	withHome(t)
	key := "unknown-location"
	real := time.Now().Add(-96 * time.Hour).UTC().Truncate(time.Second)
	writeAt(t, key, real, map[string]any{"link_mtu": 1500})

	entries, err := listDir(historyDir(key))
	if err != nil || len(entries) != 1 {
		t.Fatalf("listDir: %v (%d entries)", err, len(entries))
	}
	// Lie to the filesystem; the answer must not move.
	if err := os.Chtimes(entries[0].Path, time.Now(), time.Now()); err != nil {
		t.Fatal(err)
	}
	again, _ := listDir(historyDir(key))
	if !again[0].SavedAt.Equal(real) {
		t.Errorf("mtime changed the reported date: %s, want %s", again[0].SavedAt, real)
	}
}

// A corrupt file in the directory must be skipped, not crash the listing and
// not be silently counted as a baseline.
func TestCorruptHistoryFileIsSkipped(t *testing.T) {
	withHome(t)
	key := "unknown-location"
	writeAt(t, key, time.Now().Add(-time.Hour), map[string]any{"link_mtu": 1500})
	if err := os.WriteFile(filepath.Join(historyDir(key), "20260101T000000Z.json"),
		[]byte("{{{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := listDir(historyDir(key))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("got %d entries, want 1 — a corrupt file was counted as a baseline", len(entries))
	}
}

func TestParseWhenAcceptsWhatPeopleType(t *testing.T) {
	if n, _, err := ParseWhen("3"); err != nil || n != 3 {
		t.Errorf("\"3\" → n=%d err=%v", n, err)
	}
	if n, _, err := ParseWhen(""); err != nil || n != 1 {
		t.Errorf("empty should mean newest, got n=%d err=%v", n, err)
	}
	if _, when, err := ParseWhen("7d"); err != nil {
		t.Errorf("7d: %v", err)
	} else if d := time.Since(when); d < 6*24*time.Hour || d > 8*24*time.Hour {
		t.Errorf("7d resolved to %v ago", d)
	}
	// A bare date means the END of that day: someone typing "2026-07-14" means
	// "as it was on the 14th", not "at one second past midnight".
	_, when, err := ParseWhen("2026-07-14")
	if err != nil {
		t.Fatal(err)
	}
	if when.Hour() != 23 {
		t.Errorf("bare date resolved to %s — should be the end of that day", when)
	}
	if _, _, err := ParseWhen("last tuesday"); err == nil {
		t.Error("garbage parsed without complaint")
	} else if !strings.Contains(err.Error(), "2026-07-14") {
		t.Errorf("the error does not show the accepted forms: %v", err)
	}
}

// Existing single-file baselines must keep working: history is additive, and
// an upgrade that orphaned everyone's baseline would be a bad trade.
func TestSaveStillWritesTheLegacyBaseline(t *testing.T) {
	withHome(t)
	facts := map[string]any{"gateway_ip": "192.168.1.1", "link_mtu": 1500}
	key, err := Save(snapWith(facts), facts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(Dir(), key+".json")); err != nil {
		t.Errorf("the flat baseline file is gone — older builds could not read it: %v", err)
	}
	if _, _, _, err := Load(facts); err != nil {
		t.Errorf("Load() no longer finds the current baseline: %v", err)
	}
	if got := len(History(facts)); got != 1 {
		t.Errorf("history has %d entries after one save, want 1", got)
	}
}

func TestRenderHistoryIsHelpfulWhenEmpty(t *testing.T) {
	out := RenderHistory(nil)
	if !strings.Contains(out, "No baselines") || !strings.Contains(out, "netdiag baseline") {
		t.Errorf("the empty case does not tell the user how to fix it:\n%s", out)
	}
}
