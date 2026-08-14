// Package loadtest implements §10: throughput versus what you pay for, and
// bufferbloat — latency UNDER LOAD, which is the measurement that explains
// "the video call stutters but the speed test says everything is fine".
//
// Why this matters more than a speed number: a link can deliver its full
// contracted bandwidth and still be unusable for calls, because oversized
// router buffers queue packets instead of dropping them. Idle ping 6 ms,
// ping-while-uploading 340 ms — that is the whole story, and no consumer
// speed test reports it in words.
//
// This file is deliberately pure: measurements in, grade and verdict out, so
// the interpretation is unit-tested without needing a saturated link.
package loadtest

import (
	"fmt"
	"sort"
	"time"
)

// Grade is the DSLReports-style A–F scale technicians recognise.
type Grade string

const (
	GradeA Grade = "A" // imperceptible
	GradeB Grade = "B"
	GradeC Grade = "C"
	GradeD Grade = "D"
	GradeF Grade = "F" // calls break
)

// Result is one bufferbloat/throughput run.
type Result struct {
	IdleRTTms   float64 `json:"idle_rtt_ms"`
	LoadedRTTms float64 `json:"loaded_rtt_ms"`
	DeltaMs     float64 `json:"bloat_delta_ms"`
	Grade       Grade   `json:"bufferbloat_grade"`

	DownMbps     float64 `json:"download_mbps,omitempty"`
	UpMbps       float64 `json:"upload_mbps,omitempty"`
	ContractDown float64 `json:"contracted_down_mbps,omitempty"`

	Streams       int      `json:"streams,omitempty"`
	Samples       int      `json:"latency_samples"`
	Target        string   `json:"target"`
	Endpoint      string   `json:"endpoint,omitempty"` // which test server actually answered
	EndpointNotes []string `json:"endpoint_notes,omitempty"`
	Truncated     bool     `json:"truncated"` // run ended early (time budget/ctrl-c)
}

// GradeFor maps the latency increase under load onto the A–F scale. The
// thresholds are the widely used ones, so a technician who knows the
// DSLReports test reads the same meaning here.
func GradeFor(deltaMs float64) Grade {
	switch {
	case deltaMs < 5:
		return GradeA
	case deltaMs < 30:
		return GradeB
	case deltaMs < 60:
		return GradeC
	case deltaMs < 200:
		return GradeD
	default:
		return GradeF
	}
}

// Median is used for both idle and loaded latency: the mean is hostage to a
// single outlier, and one 900 ms spike must not turn a healthy link into an F.
func Median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	mid := len(s) / 2
	if len(s)%2 == 1 {
		return s[mid]
	}
	return (s[mid-1] + s[mid]) / 2
}

// Mbps converts bytes moved over a duration into megabits per second.
func Mbps(bytes int64, d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(bytes) * 8 / d.Seconds() / 1e6
}

// Verdict is the sentence a technician can paste into a ticket: what the
// numbers mean, and what to do about them.
func (r Result) Verdict() string {
	bloat := ""
	switch r.Grade {
	case GradeA:
		bloat = fmt.Sprintf("Bufferbloat: none worth reporting (latency %.0f ms idle → %.0f ms under load, grade A). "+
			"Calls and gaming will not suffer from queueing on this link.",
			r.IdleRTTms, r.LoadedRTTms)
	case GradeB:
		bloat = fmt.Sprintf("Bufferbloat: mild (%.0f ms → %.0f ms under load, +%.0f ms, grade B). "+
			"Usually unnoticeable; heavy uploads may add a slight lag to calls.",
			r.IdleRTTms, r.LoadedRTTms, r.DeltaMs)
	case GradeC:
		bloat = fmt.Sprintf("Bufferbloat: noticeable (%.0f ms → %.0f ms under load, +%.0f ms, grade C). "+
			"Video calls will stutter while someone is uploading. Fix: enable SQM/fq_codel on the router.",
			r.IdleRTTms, r.LoadedRTTms, r.DeltaMs)
	case GradeD:
		bloat = fmt.Sprintf("Bufferbloat: bad (%.0f ms → %.0f ms under load, +%.0f ms, grade D). "+
			"This is why calls break up when the connection is busy — the router queues instead of dropping. "+
			"Fix: enable SQM/fq_codel and set it just below the real line rate.",
			r.IdleRTTms, r.LoadedRTTms, r.DeltaMs)
	default:
		bloat = fmt.Sprintf("Bufferbloat: severe (%.0f ms → %.0f ms under load, +%.0f ms, grade F). "+
			"Any upload or download makes calls, gaming and remote sessions unusable, even though the "+
			"speed test looks fine. Fix: enable SQM/fq_codel on the router (or replace it if it cannot).",
			r.IdleRTTms, r.LoadedRTTms, r.DeltaMs)
	}

	if r.DownMbps <= 0 {
		return bloat
	}
	thr := fmt.Sprintf(" Throughput: %.0f Mbps down.", r.DownMbps)
	if r.ContractDown > 0 {
		pct := r.DownMbps / r.ContractDown * 100
		switch {
		case pct < 20:
			// Below a fifth of contract, suspect the MEASUREMENT before the
			// line. A public test server, a distant path or a busy endpoint
			// caps out long before a fast connection does — the field run
			// read 2 Mbps on a 500 Mbps line and blamed the ISP for it.
			thr = fmt.Sprintf(" Throughput: %.0f Mbps against a %.0f Mbps contract (%.0f%%) — "+
				"but that is so far below the contract that the TEST is the more likely limit, "+
				"not the line: a public server over %d stream(s) cannot fill a fast connection. "+
				"Re-test on a cable, against a nearer server (-url), before saying anything to the ISP.",
				r.DownMbps, r.ContractDown, pct, maxInt(r.Streams, 1))
		case pct < 50:
			thr = fmt.Sprintf(" Throughput: %.0f Mbps against a %.0f Mbps contract — %.0f%% of what is paid for. "+
				"Worth checking, but confirm on a cable and against a second server before "+
				"raising it with the ISP.",
				r.DownMbps, r.ContractDown, pct)
		case pct < 80:
			thr = fmt.Sprintf(" Throughput: %.0f Mbps against a %.0f Mbps contract (%.0f%%) — under contract but "+
				"within the range Wi-Fi and shared lines usually explain. Retest on a cable before escalating.",
				r.DownMbps, r.ContractDown, pct)
		default:
			thr = fmt.Sprintf(" Throughput: %.0f Mbps against a %.0f Mbps contract (%.0f%%) — the line is delivering.",
				r.DownMbps, r.ContractDown, pct)
		}
	}
	return bloat + thr
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Honest returns the caveats that belong next to every result, because a
// throughput number measured over Wi-Fi from one laptop is not a verdict on
// the ISP's line.
func (r Result) Honest(overWifi bool) []string {
	var out []string
	if overWifi {
		out = append(out, "measured over Wi-Fi — the radio, not the line, may be the ceiling; "+
			"retest on a cable before blaming the ISP")
	}
	if r.Samples < 10 {
		out = append(out, fmt.Sprintf("only %d latency samples under load — treat the grade as indicative", r.Samples))
	}
	if r.Truncated {
		out = append(out, "the run was cut short, so the numbers cover less traffic than intended")
	}
	if r.Streams > 0 {
		out = append(out, fmt.Sprintf("throughput measured over %d parallel stream(s) to one public server — "+
			"this is a floor, not a ceiling: your line may be faster than this shows", r.Streams))
	}
	out = append(out, "one machine's view: other traffic on the network during the test affects both numbers")
	return out
}
