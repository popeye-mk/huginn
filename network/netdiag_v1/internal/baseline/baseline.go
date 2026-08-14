// Package baseline is the v1.2 release (spec §18): the motion-detector.
// `netdiag baseline` saves the current network state as known-good for THIS
// location; `netdiag scan -diff` surfaces what changed against it; and
// `netdiag compare good.json bad.json` (§7.1) is the same diff engine
// pointed at a second machine instead of a second point in time.
// Same code, third use — exactly as the spec prescribes.
package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"netdiag/internal/schema"
)

// Dir: local, next to the feedback file; overridable for tests/USB runs.
func Dir() string {
	if p := os.Getenv("NETDIAG_BASELINES"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "netdiag_baselines"
	}
	return filepath.Join(home, ".netdiag", "baselines")
}

var unsafeChars = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// LocationKey identifies "this network" for baseline storage. The gateway
// MAC is the strongest passive identity (survives DHCP renumbering);
// SSID and gateway IP are the fallbacks.
func LocationKey(facts map[string]any) string {
	keys := candidateKeys(facts)
	if len(keys) == 0 {
		return "unknown-location"
	}
	return keys[0]
}

// candidateKeys: every identity this network answers to. Load tries them
// all — when the gateway is DEAD its MAC fact vanishes, and that broken
// moment is exactly when the baseline must still be findable.
func candidateKeys(facts map[string]any) []string {
	var out []string
	for _, k := range []string{"gateway_mac", "wifi_ssid", "gateway_ip"} {
		if v, ok := facts[k].(string); ok && v != "" {
			out = append(out, unsafeChars.ReplaceAllString(v, "_"))
		}
	}
	if len(out) == 0 {
		out = append(out, "unknown-location")
	}
	return out
}

type stored struct {
	SavedAt     time.Time        `json:"saved_at"`
	LocationKey string           `json:"location_key"`
	Snapshot    *schema.Snapshot `json:"snapshot"`
}

// Save writes the snapshot as this location's baseline, under EVERY
// identity candidate — so a later broken state (dead gateway = no MAC
// fact) still finds it via SSID or gateway IP.
func Save(snap *schema.Snapshot, facts map[string]any) (string, error) {
	keys := candidateKeys(facts)
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		return keys[0], err
	}
	b, err := json.MarshalIndent(stored{time.Now().UTC(), keys[0], snap}, "", "  ")
	if err != nil {
		return keys[0], err
	}
	for _, key := range keys {
		if err := os.WriteFile(filepath.Join(Dir(), key+".json"), b, 0o600); err != nil {
			return keys[0], err
		}
	}
	// Additionally keep a timestamped copy, so `-diff` can answer "what changed
	// since Tuesday" and not only "since the last time someone pressed save".
	// A history failure must NOT fail the save: the current baseline is the
	// thing that matters, and losing it because a history directory could not
	// be written would be a worse tool than one with no history at all.
	if err := SaveHistory(snap, keys[0], DefaultKeep); err != nil {
		return keys[0], nil
	}
	return keys[0], nil
}

// Load returns the baseline for the location the given facts describe,
// trying every identity candidate.
func Load(facts map[string]any) (*schema.Snapshot, time.Time, string, error) {
	var lastErr error
	for _, key := range candidateKeys(facts) {
		b, err := os.ReadFile(filepath.Join(Dir(), key+".json"))
		if err != nil {
			lastErr = err
			continue
		}
		var s stored
		if err := json.Unmarshal(b, &s); err != nil {
			lastErr = err
			continue
		}
		return s.Snapshot, s.SavedAt, key, nil
	}
	return nil, time.Time{}, LocationKey(facts), lastErr
}

// LoadSnapshotFile reads a `-save` snapshot (for `compare`). It accepts both
// the raw snapshot and the baseline wrapper.
func LoadSnapshotFile(path string) (*schema.Snapshot, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s stored
	if err := json.Unmarshal(b, &s); err == nil && s.Snapshot != nil {
		return s.Snapshot, nil
	}
	var snap schema.Snapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		return nil, fmt.Errorf("%s: not a netdiag snapshot: %w", path, err)
	}
	if snap.SchemaVersion == "" {
		return nil, fmt.Errorf("%s: not a netdiag snapshot (no schema_version)", path)
	}
	return &snap, nil
}
