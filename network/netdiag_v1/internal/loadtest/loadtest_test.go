package loadtest

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestGradeBoundaries(t *testing.T) {
	cases := []struct {
		delta float64
		want  Grade
	}{
		{0, GradeA}, {4.9, GradeA}, {5, GradeB}, {29.9, GradeB},
		{30, GradeC}, {59.9, GradeC}, {60, GradeD}, {199.9, GradeD},
		{200, GradeF}, {334, GradeF},
	}
	for _, c := range cases {
		if got := GradeFor(c.delta); got != c.want {
			t.Errorf("delta %.1f ms → %s, want %s", c.delta, got, c.want)
		}
	}
}

// One spike must not condemn a healthy link — that is why the median is used
// rather than the mean.
func TestMedianResistsOutliers(t *testing.T) {
	quiet := []float64{6, 7, 6, 900, 6, 7}
	if got := Median(quiet); got > 10 {
		t.Errorf("median %v was dragged up by the outlier", got)
	}
}

func TestMbps(t *testing.T) {
	// 12.5 MB in 1 s = 100 Mbps.
	if got := Mbps(12_500_000, time.Second); got < 99 || got > 101 {
		t.Errorf("got %.1f Mbps, want ~100", got)
	}
	if got := Mbps(1000, 0); got != 0 {
		t.Errorf("zero duration must not divide by zero: %v", got)
	}
}

// The verdict has to name the fix, not just the number — an F with no
// mention of SQM is a measurement, not a diagnosis.
func TestVerdictNamesTheFix(t *testing.T) {
	r := Result{IdleRTTms: 6, LoadedRTTms: 340, DeltaMs: 334, Grade: GradeF}
	v := r.Verdict()
	for _, want := range []string{"severe", "grade F", "SQM"} {
		if !strings.Contains(v, want) {
			t.Errorf("verdict missing %q: %s", want, v)
		}
	}
}

// Under-delivery against a contract is the ticket people actually raise.
func TestVerdictComparesAgainstContract(t *testing.T) {
	r := Result{IdleRTTms: 8, LoadedRTTms: 12, DeltaMs: 4, Grade: GradeA,
		DownMbps: 43, ContractDown: 200}
	v := r.Verdict()
	if !strings.Contains(v, "22%") || !strings.Contains(v, "ISP") {
		t.Errorf("under-delivery not called out: %s", v)
	}
	// Delivering the contract must NOT be reported as a problem.
	ok := Result{Grade: GradeA, DownMbps: 195, ContractDown: 200}
	if strings.Contains(ok.Verdict(), "ISP") {
		t.Errorf("a healthy line was sent to the ISP: %s", ok.Verdict())
	}
}

// Wi-Fi is the usual reason a throughput number is not the ISP's fault.
func TestHonestCaveats(t *testing.T) {
	r := Result{Samples: 4, Truncated: true}
	got := strings.Join(r.Honest(true), " | ")
	for _, want := range []string{"Wi-Fi", "indicative", "cut short"} {
		if !strings.Contains(got, want) {
			t.Errorf("caveat %q missing from: %s", want, got)
		}
	}
}

// No idle samples (ICMP blocked) must be an honest error, never a grade
// invented from nothing.
func TestNoSamplesIsAnErrorNotAnA(t *testing.T) {
	cfg := DefaultConfig(func(string, time.Duration) (time.Duration, error) {
		return 0, context.DeadlineExceeded
	})
	cfg.IdleWindow = 300 * time.Millisecond
	// Point at something unreachable so the run cannot depend on the network,
	// but keep the failure in the pre-flight rather than the ping phase.
	cfg.DownloadURL = "http://127.0.0.1:1/nothing"
	cfg.Fallbacks = nil
	res, err := cfg.Run(context.Background())
	if err == nil {
		t.Fatal("expected an error when nothing could be measured")
	}
	if res.Grade != "" {
		t.Errorf("invented grade %q with no samples", res.Grade)
	}
}

// A cancelled run still returns what it measured, marked as truncated.
func TestCancelledRunKeepsEvidence(t *testing.T) {
	cfg := DefaultConfig(func(string, time.Duration) (time.Duration, error) {
		return 7 * time.Millisecond, nil
	})
	cfg.IdleWindow = 600 * time.Millisecond
	cfg.LoadWindow = 400 * time.Millisecond
	cfg.DownloadURL = "http://127.0.0.1:1/nothing" // guaranteed to fail fast
	cfg.Fallbacks = nil                            // no rescue endpoints in the test
	_, err := cfg.Run(context.Background())
	// The endpoint is unreachable, so this must be an honest error that says
	// so — caught by the pre-flight before any measurement window runs.
	if err == nil {
		t.Fatal("unreachable endpoint should be reported, not hidden")
	}
	if !strings.Contains(err.Error(), "no usable test endpoint") {
		t.Errorf("error should name the endpoint problem: %v", err)
	}
}

// Field regression (Win 11, 0.9.0): the download moved 0 bytes because that
// VM had no path to the endpoint, and the tool still reported "grade A —
// calls and gaming will not suffer". A grade from a link that was never
// loaded is a confident lie; it must be an error instead.
func TestNoTransferMeansNoGrade(t *testing.T) {
	cfg := DefaultConfig(func(string, time.Duration) (time.Duration, error) {
		return 34 * time.Millisecond, nil // latency measurable, transfer not
	})
	cfg.IdleWindow = 400 * time.Millisecond
	cfg.LoadWindow = 2 * time.Second
	cfg.DownloadURL = "http://127.0.0.1:1/nothing" // nothing will be served
	cfg.Fallbacks = nil

	res, err := cfg.Run(context.Background())
	if err == nil {
		t.Fatal("an unloaded link produced a grade instead of an error")
	}
	if res.Grade != "" {
		t.Errorf("grade %q invented with no transfer", res.Grade)
	}
	// The message must name the CAUSE, not just the symptom: "moved almost
	// nothing" with no reason is unactionable (field run on the laptop).
	for _, want := range []string{"no usable test endpoint", "connection refused"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should name the real cause, got: %v", err)
		}
	}
}

// Field regression (laptop, 0.9.4): a distant public server delivered 2 Mbps
// on a 500 Mbps line and the verdict told the user to raise it with the ISP.
// A measurement that far below contract indicts the TEST, not the line.
func TestAbsurdlyLowThroughputBlamesTheTestNotTheISP(t *testing.T) {
	r := Result{Grade: GradeA, DownMbps: 2, ContractDown: 500, Streams: 4}
	v := r.Verdict()
	if strings.Contains(v, "Worth raising with the ISP") {
		t.Errorf("blamed the ISP for a slow test server: %s", v)
	}
	for _, want := range []string{"the TEST is the more likely limit", "Re-test"} {
		if !strings.Contains(v, want) {
			t.Errorf("verdict should question the measurement, got: %s", v)
		}
	}
	// A genuinely under-delivering line (say 40%) is still reported — but
	// with a confirmation step, not an accusation.
	mid := Result{Grade: GradeA, DownMbps: 200, ContractDown: 500, Streams: 4}
	if !strings.Contains(mid.Verdict(), "confirm on a cable") {
		t.Errorf("mid-range under-delivery lost its caveat: %s", mid.Verdict())
	}
}
