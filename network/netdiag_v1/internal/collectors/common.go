// Package collectors: the only OS-specific layer (spec §17.4).
// Everything above it sees the same schema.
package collectors

import "netdiag/internal/run"

// ForThisOS returns the passive set for the current OS.
// On platforms without real collectors yet, stubs report
// skipped/not_applicable — "absence is never health".
func ForThisOS() []run.Collector { return platformCollectors() }

// EventWindowHours is the retrospective window for event mining, settable
// via the -since flag (§18 v1.1).
var EventWindowHours = 24
