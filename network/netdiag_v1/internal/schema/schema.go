// Package schema defines the versioned snapshot envelope shared by every
// collector and, later, by the machine diagnostician (parent spec v5 §4.3).
package schema

import "time"

// 0.2.0: v1 adds fact keys (new collectors) — envelope unchanged, minor bump.
const SchemaVersion = "0.2.0"

// Status values for the per-collector envelope. Absence is never health:
// a collector that did not run reports skipped/timeout/error with a reason.
const (
	StatusOK      = "ok"
	StatusSkipped = "skipped"
	StatusTimeout = "timeout"
	StatusError   = "error"
)

// Privilege levels (spec §3.1).
const (
	PrivUnprivileged = "unprivileged"
	PrivElevated     = "elevated"
)

// CollectorResult is the per-collector envelope (spec §4).
type CollectorResult struct {
	Status         string         `json:"status"`
	Reason         string         `json:"reason,omitempty"`
	DurationMS     int64          `json:"duration_ms"`
	PrivilegeLevel string         `json:"privilege_level"`
	Data           map[string]any `json:"data,omitempty"`
}

// Snapshot is the single structured blob (spec §4.3) — same outer shape
// regardless of OS, versioned from day one.
type Snapshot struct {
	SchemaVersion string                     `json:"schema_version"`
	Tool          string                     `json:"tool"`
	ToolVersion   string                     `json:"tool_version"`
	CollectedAt   time.Time                  `json:"collected_at"`
	Hostname      string                     `json:"hostname"`
	OS            string                     `json:"os"`
	Collectors    map[string]CollectorResult `json:"collectors"`
}

// Facts flattens every ok collector's Data into one namespace for the
// rules engine. Collector authors keep keys globally unique on purpose.
func (s *Snapshot) Facts() map[string]any {
	facts := map[string]any{}
	for _, c := range s.Collectors {
		if c.Status != StatusOK {
			continue
		}
		for k, v := range c.Data {
			facts[k] = v
		}
	}
	return facts
}
