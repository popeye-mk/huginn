package baseline

// Historical baselines (roadmap item 7).
//
// Until now a location had exactly one baseline and each save overwrote it, so
// `-diff` could only answer "what changed since the last time someone pressed
// save?" — a question whose answer silently got worse every time the tool was
// used. The much better question, and the one people actually ask, is "what
// changed since Tuesday, when it worked?"
//
// The design constraint that shaped this: DO NOT BREAK EXISTING BASELINES.
// `<key>.json` is still written exactly as before and is still what Load()
// reads, so a baseline saved by 0.9.15 keeps working and an older binary can
// still read one written today. History is additive — a directory of
// timestamped copies alongside it — rather than a new format everyone has to
// migrate to.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"netdiag/internal/schema"
)

// DefaultKeep is how many historical baselines a location retains. Ten covers
// "it worked last week" without letting a machine that runs the tool hourly
// fill a home directory.
const DefaultKeep = 10

// Entry is one historical baseline.
type Entry struct {
	SavedAt time.Time
	Key     string
	Path    string
}

// Age is how long ago it was taken, rounded for display.
func (e Entry) Age() time.Duration { return time.Since(e.SavedAt).Round(time.Minute) }

// historyDir holds the timestamped copies for one location key.
func historyDir(key string) string { return filepath.Join(Dir(), "history", key) }

// SaveHistory records a timestamped copy alongside the current baseline and
// prunes to keep. It is called by Save; exported for tests.
func SaveHistory(snap *schema.Snapshot, key string, keep int) error {
	if keep <= 0 {
		keep = DefaultKeep
	}
	dir := historyDir(key)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	now := time.Now().UTC()
	b, err := json.MarshalIndent(stored{now, key, snap}, "", "  ")
	if err != nil {
		return err
	}
	// Second precision in the filename, so two saves inside one second do not
	// collide silently — the later one must not vanish.
	name := now.Format("20060102T150405Z") + ".json"
	path := filepath.Join(dir, name)
	for i := 1; ; i++ {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			break
		}
		path = filepath.Join(dir, fmt.Sprintf("%s-%d.json", strings.TrimSuffix(name, ".json"), i))
		if i > 100 {
			break
		}
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return err
	}
	return prune(dir, keep)
}

// prune deletes the oldest entries beyond keep. Failure to prune is not
// failure to save: a full disk should not lose the baseline just taken.
func prune(dir string, keep int) error {
	entries, err := listDir(dir)
	if err != nil || len(entries) <= keep {
		return nil
	}
	for _, e := range entries[keep:] { // listDir is newest-first
		_ = os.Remove(e.Path)
	}
	return nil
}

// History returns this location's baselines, newest first.
func History(facts map[string]any) []Entry {
	for _, key := range candidateKeys(facts) {
		if entries, err := listDir(historyDir(key)); err == nil && len(entries) > 0 {
			return entries
		}
	}
	return nil
}

func listDir(dir string) ([]Entry, error) {
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	key := filepath.Base(dir)
	var out []Entry
	for _, de := range des {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, de.Name())
		// The timestamp comes from the FILE CONTENTS, not the name. A copied
		// or restored directory keeps mtimes that lie, and a baseline dated
		// wrongly would be compared against the wrong day without saying so.
		when, err := savedAtOf(path)
		if err != nil {
			continue
		}
		out = append(out, Entry{SavedAt: when, Key: key, Path: path})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SavedAt.After(out[j].SavedAt) })
	return out, nil
}

func savedAtOf(path string) (time.Time, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, err
	}
	var s stored
	if err := json.Unmarshal(b, &s); err != nil {
		return time.Time{}, err
	}
	if s.SavedAt.IsZero() {
		return time.Time{}, fmt.Errorf("%s: no saved_at", path)
	}
	return s.SavedAt, nil
}

// LoadNth returns the nth-newest historical baseline (1 = newest).
func LoadNth(facts map[string]any, n int) (*schema.Snapshot, Entry, error) {
	entries := History(facts)
	if len(entries) == 0 {
		return nil, Entry{}, fmt.Errorf("no baseline history for this location yet")
	}
	if n < 1 || n > len(entries) {
		return nil, Entry{}, fmt.Errorf("only %d baseline(s) kept for this location — asked for #%d", len(entries), n)
	}
	e := entries[n-1]
	snap, err := LoadSnapshotFile(e.Path)
	return snap, e, err
}

// LoadNearest returns the newest baseline taken at or before when. It never
// silently substitutes a LATER one: "what did it look like on Tuesday" must
// not be answered with Thursday's data.
func LoadNearest(facts map[string]any, when time.Time) (*schema.Snapshot, Entry, error) {
	entries := History(facts)
	if len(entries) == 0 {
		return nil, Entry{}, fmt.Errorf("no baseline history for this location yet")
	}
	for _, e := range entries { // newest first
		if !e.SavedAt.After(when) {
			snap, err := LoadSnapshotFile(e.Path)
			return snap, e, err
		}
	}
	oldest := entries[len(entries)-1]
	return nil, Entry{}, fmt.Errorf(
		// Local time in BOTH halves: the list command prints local, and a
		// message mixing local and UTC makes the user think a baseline they
		// can see does not exist.
		"no baseline from %s or earlier — the oldest kept here is %s",
		when.Local().Format("2006-01-02"), oldest.SavedAt.Local().Format("2006-01-02 15:04"))
}

// ParseWhen accepts what a person types: "3" (the 3rd newest), a date, or a
// duration like "7d"/"48h" meaning "as it was that long ago".
func ParseWhen(s string) (n int, when time.Time, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 1, time.Time{}, nil
	}
	if n, e := parseInt(s); e == nil {
		return n, time.Time{}, nil
	}
	for _, layout := range []string{"2006-01-02 15:04", "2006-01-02T15:04", "2006-01-02"} {
		if t, e := time.ParseInLocation(layout, s, time.Local); e == nil {
			// A bare date means "as it was at the END of that day", which is
			// what someone typing "2026-07-14" means by "on the 14th".
			if layout == "2006-01-02" {
				t = t.Add(24*time.Hour - time.Second)
			}
			return 0, t, nil
		}
	}
	if d, e := parseDuration(s); e == nil {
		return 0, time.Now().Add(-d), nil
	}
	return 0, time.Time{}, fmt.Errorf(
		"cannot read %q as a baseline: use a number (2 = second newest), a date "+
			"(2026-07-14), or an age (7d, 48h)", s)
}

func parseInt(s string) (int, error) {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return 0, err
	}
	if fmt.Sprint(n) != s {
		return 0, fmt.Errorf("not a plain integer")
	}
	return n, nil
}

// parseDuration adds days to time.ParseDuration, because "7d" is what people
// type and Go refuses it.
func parseDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		var days float64
		if _, err := fmt.Sscanf(strings.TrimSuffix(s, "d"), "%g", &days); err == nil {
			return time.Duration(days * 24 * float64(time.Hour)), nil
		}
	}
	return time.ParseDuration(s)
}

// RenderHistoryFor is RenderHistory with the network named in human terms.
func RenderHistoryFor(entries []Entry, facts map[string]any) string {
	if len(entries) == 0 {
		return RenderHistory(entries)
	}
	return fmt.Sprintf("  %s\n\n", capitalise(Describe(facts))) + RenderHistory(entries)
}

// RenderHistory lists what is kept, for `netdiag baseline -list`.
func RenderHistory(entries []Entry) string {
	if len(entries) == 0 {
		return "  No baselines kept for this location yet. Run `netdiag baseline` " +
			"while it is working, so a later run has something to compare against.\n"
	}
	var b strings.Builder
	noun := "snapshots"
	if len(entries) == 1 {
		noun = "snapshot"
	}
	fmt.Fprintf(&b, "  %d saved %s, newest first:\n\n", len(entries), noun)
	for i, e := range entries {
		fmt.Fprintf(&b, "  %2d. %s   (%s ago)\n", i+1,
			e.SavedAt.Local().Format("2006-01-02 15:04"), humanAge(e.Age()))
	}
	fmt.Fprintf(&b, "\n  Compare today against one of them:\n")
	fmt.Fprintf(&b, "    netdiag -diff              (against the newest)\n")
	fmt.Fprintf(&b, "    netdiag -diff -against 2   (against #2 in this list)\n")
	fmt.Fprintf(&b, "    netdiag -diff -against 7d  (as it was a week ago)\n")
	return b.String()
}

func humanAge(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// Describe names this network the way a person would, for output that a human
// reads. The storage KEY is a filesystem-safe MAC or SSID — correct, stable,
// and meaningless on screen: "unknown-location" and "aa_bb_cc_dd_ee_ff" both
// tell the reader nothing about which network they are looking at.
func capitalise(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func Describe(facts map[string]any) string {
	str := func(k string) string {
		v, _ := facts[k].(string)
		return v
	}
	if ssid := str("wifi_ssid"); ssid != "" {
		return fmt.Sprintf("the Wi-Fi network %q", ssid)
	}
	if gw := str("gateway_ip"); gw != "" {
		return fmt.Sprintf("the network behind gateway %s", gw)
	}
	if mac := str("gateway_mac"); mac != "" {
		return fmt.Sprintf("the network behind router %s", mac)
	}
	// No gateway at all is itself worth saying: it is usually WHY the person is
	// running the tool, and "unknown-location" hides that.
	return "this machine's network (no gateway seen — it may be offline)"
}
