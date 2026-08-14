// Package run executes collectors under the envelope discipline:
// every collector gets a timeout, and a timeout is itself reported
// (status: timeout), never silence.
package run

import (
	"context"
	"os"
	"runtime"
	"time"

	"netdiag/internal/schema"
)

// Collector is anything that can populate one envelope entry.
type Collector interface {
	Name() string
	Privilege() string
	Collect(ctx context.Context) (map[string]any, error)
}

// SkipError lets a collector report an honest skip (not applicable /
// insufficient privilege) instead of an error.
type SkipError struct{ ReasonText string }

func (e SkipError) Error() string { return e.ReasonText }

const perCollectorTimeout = 5 * time.Second

// TimeLimiter lets a multi-probe collector claim a larger slice of the 30 s
// passive budget (§16) than the 5 s default.
type TimeLimiter interface{ Timeout() time.Duration }

// Progress, when set, is called before each collector runs. A full sweep
// takes most of the 30 s budget and printed nothing until it finished, which
// reads as "the program froze" — the fix is to say what is happening. Nil by
// default so tests, JSON output and the watch sampler stay silent.
var Progress func(name string, idx, total int)

// All runs every collector sequentially (v0: sequential is fine inside the
// 30 s passive budget) and returns the snapshot.
func All(collectors []Collector, toolVersion string) *schema.Snapshot {
	host, _ := os.Hostname()
	snap := &schema.Snapshot{
		SchemaVersion: schema.SchemaVersion,
		Tool:          "netdiag",
		ToolVersion:   toolVersion,
		CollectedAt:   time.Now().UTC(),
		Hostname:      host,
		OS:            runtime.GOOS,
		Collectors:    map[string]schema.CollectorResult{},
	}
	for i, c := range collectors {
		if Progress != nil {
			Progress(c.Name(), i+1, len(collectors))
		}
		snap.Collectors[c.Name()] = runOne(c)
	}
	return snap
}

// Only runs the named subset — the sampling path for `watch` (§9), where a
// tick must stay far inside the interval and the heavy one-shot collectors
// (event mining, firewall, proxy, AD) have nothing to say every 5 seconds.
// Unknown names are ignored rather than erroring: the caller asks for what it
// wants and gets whatever this OS actually implements.
func Only(collectors []Collector, names []string, toolVersion string) *schema.Snapshot {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	var subset []Collector
	for _, c := range collectors {
		if want[c.Name()] {
			subset = append(subset, c)
		}
	}
	return All(subset, toolVersion)
}

func runOne(c Collector) schema.CollectorResult {
	timeout := perCollectorTimeout
	if tl, ok := c.(TimeLimiter); ok {
		timeout = tl.Timeout()
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	data, err := c.Collect(ctx)
	res := schema.CollectorResult{
		DurationMS:     time.Since(start).Milliseconds(),
		PrivilegeLevel: c.Privilege(),
		Data:           data,
	}
	switch {
	case err == nil:
		res.Status = schema.StatusOK
	case ctx.Err() == context.DeadlineExceeded:
		res.Status = schema.StatusTimeout
		res.Reason = "collector exceeded its timeout"
	default:
		if se, ok := err.(SkipError); ok {
			res.Status = schema.StatusSkipped
			res.Reason = se.ReasonText
		} else {
			res.Status = schema.StatusError
			res.Reason = err.Error()
		}
	}
	return res
}
