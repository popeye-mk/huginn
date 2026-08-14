package watch

import (
	"strings"
	"testing"
	"time"
)

func b(v bool) *bool       { return &v }
func f(v float64) *float64 { return &v }

var t0 = time.Date(2026, 7, 19, 15, 0, 0, 0, time.UTC)

func at(n int) time.Time { return t0.Add(time.Duration(n) * 10 * time.Second) }

// A flap is two events: the drop, and the recovery that proves it was a flap.
func TestLinkFlapIsCaughtAndClosed(t *testing.T) {
	w := New(Normal{})
	w.Add(Sample{At: at(0), LinkUp: b(true)})
	w.Add(Sample{At: at(1), LinkUp: b(false)})
	w.Add(Sample{At: at(2), LinkUp: b(false)}) // still down: not a second event
	w.Add(Sample{At: at(3), LinkUp: b(true)})
	if len(w.Events) != 2 {
		t.Fatalf("want 2 events (down, up), got %d: %+v", len(w.Events), w.Events)
	}
	if w.Events[0].Kind != "link_down" || w.Events[1].Kind != "link_up" {
		t.Errorf("wrong kinds: %+v", w.Events)
	}
	if !strings.Contains(w.Verdict(), "physical link dropped") {
		t.Errorf("verdict missed the link story: %q", w.Verdict())
	}
}

// Baseline-aware: 8% loss is an event where normal is 0%, but not where
// normal is already 5% — the location's own normal is the yardstick (§5.2).
func TestLossJudgedAgainstLocationNormal(t *testing.T) {
	quiet := New(Normal{Known: true, LossPct: 0})
	quiet.Add(Sample{At: at(0), GatewayLoss: f(12)})
	if len(quiet.Events) != 1 {
		t.Errorf("12%% loss over a 0%% normal should fire: %+v", quiet.Events)
	}
	lossy := New(Normal{Known: true, LossPct: 8})
	lossy.Add(Sample{At: at(0), GatewayLoss: f(12)})
	if len(lossy.Events) != 0 {
		t.Errorf("12%% loss over an 8%% normal should not fire: %+v", lossy.Events)
	}
}

// An episode opens once and closes once, carrying its peak — not one event
// per tick for as long as it lasts.
func TestLossEpisodeOpensAndClosesOnce(t *testing.T) {
	w := New(Normal{})
	w.Add(Sample{At: at(0), GatewayLoss: f(0)})
	w.Add(Sample{At: at(1), GatewayLoss: f(20)})
	w.Add(Sample{At: at(2), GatewayLoss: f(45)})
	w.Add(Sample{At: at(3), GatewayLoss: f(30)})
	w.Add(Sample{At: at(4), GatewayLoss: f(0)})
	if len(w.Events) != 2 {
		t.Fatalf("want open+close, got %d: %+v", len(w.Events), w.Events)
	}
	if !strings.Contains(w.Events[1].What, "45%") {
		t.Errorf("recovery should carry the peak: %q", w.Events[1].What)
	}
}

// The finding a snapshot can never make: this recurs on a rhythm.
func TestPeriodicityDetected(t *testing.T) {
	w := New(Normal{})
	// A loss spike every 30 minutes, five times, with realistic jitter.
	base := t0
	for i, off := range []time.Duration{0, 1801, 3598, 5405, 7200} {
		tick := base.Add(off * time.Second)
		w.Add(Sample{At: tick.Add(-time.Second), GatewayLoss: f(0)})
		w.Add(Sample{At: tick, GatewayLoss: f(30)})
		_ = i
	}
	var found *Periodicity
	for _, p := range w.Periodic() {
		if p.Kind == "loss_spike" {
			pp := p
			found = &pp
		}
	}
	if found == nil {
		t.Fatal("no periodicity for the repeated loss spikes")
	}
	if !found.Regular {
		t.Errorf("regular ~30m recurrence not called regular: gap %s", found.MeanGap)
	}
	if found.MeanGap < 29*time.Minute || found.MeanGap > 31*time.Minute {
		t.Errorf("mean gap %s, want ~30m", found.MeanGap)
	}
	if !strings.Contains(w.Summary(), "Rhythm") {
		t.Error("summary omitted the rhythm section")
	}
}

// Irregular recurrence must NOT be called periodic — over-claiming a rhythm
// sends the technician hunting for a scheduled job that doesn't exist.
func TestIrregularIsNotCalledPeriodic(t *testing.T) {
	w := New(Normal{})
	for _, off := range []time.Duration{0, 60, 900, 950, 4000} {
		tick := t0.Add(off * time.Second)
		w.Add(Sample{At: tick.Add(-time.Second), GatewayLoss: f(0)})
		w.Add(Sample{At: tick, GatewayLoss: f(30)})
	}
	for _, p := range w.Periodic() {
		if p.Kind == "loss_spike" && p.Regular {
			t.Errorf("irregular gaps called regular: %s", p.MeanGap)
		}
	}
}

// Absence is never health: a collector that could not measure must show up as
// unmeasured, and must not look like a healthy sample.
func TestUnmeasuredIsNotGreen(t *testing.T) {
	w := New(Normal{})
	w.Add(Sample{At: at(0)}) // everything nil
	if len(w.Events) != 0 {
		t.Errorf("empty sample invented events: %+v", w.Events)
	}
	s := w.Summary()
	for _, want := range []string{"unmeasured", "NOT green"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary missing %q:\n%s", want, s)
		}
	}
}

// The security-relevant identity changes fire loudly.
func TestIdentityDriftEvents(t *testing.T) {
	w := New(Normal{})
	w.Add(Sample{At: at(0), GatewayMAC: "aa:bb:cc:11:22:33", IPv4: "192.168.1.10", DHCPServer: "192.168.1.1"})
	w.Add(Sample{At: at(1), GatewayMAC: "de:ad:be:ef:00:01", IPv4: "192.168.1.55", DHCPServer: "192.168.1.99"})
	kinds := map[string]bool{}
	for _, e := range w.Events {
		kinds[e.Kind] = true
	}
	for _, want := range []string{"gateway_mac_change", "address_change", "dhcp_server_change"} {
		if !kinds[want] {
			t.Errorf("missing %s: %+v", want, w.Events)
		}
	}
	// All three are critical; the verdict must lead with one of the
	// security-relevant ones rather than the benign address change.
	v := w.Verdict()
	if !strings.Contains(v, "MAC address changed") && !strings.Contains(v, "DHCP server") {
		t.Errorf("verdict should lead with the security-relevant change: %q", v)
	}
}

// Wi-Fi roaming is the classic "it stalls for a second sometimes".
func TestRoamAndRSSIDrop(t *testing.T) {
	w := New(Normal{})
	w.Add(Sample{At: at(0), WifiBSSID: "aa:11:22:33:44:55", WifiRSSI: f(-48)})
	w.Add(Sample{At: at(1), WifiBSSID: "bb:11:22:33:44:66", WifiRSSI: f(-67)})
	kinds := map[string]bool{}
	for _, e := range w.Events {
		kinds[e.Kind] = true
	}
	if !kinds["wifi_roam"] || !kinds["wifi_rssi_drop"] {
		t.Errorf("roam/RSSI drop not both caught: %+v", w.Events)
	}
}

// A clean window says so honestly — and refuses to call it proof of health.
func TestCleanRunIsNotProofOfHealth(t *testing.T) {
	w := New(Normal{Known: true, LossPct: 0, RTTms: 3})
	for i := 0; i < 10; i++ {
		w.Add(Sample{At: at(i), LinkUp: b(true), GatewayLoss: f(0), GatewayRTT: f(3), DNSOK: b(true), DNSLatency: f(20)})
	}
	s := w.Summary()
	if !strings.Contains(s, "No events") {
		t.Errorf("clean run should say so:\n%s", s)
	}
	if !strings.Contains(w.Verdict(), "not proof of health") {
		t.Errorf("verdict over-claimed health: %q", w.Verdict())
	}
}

// Smoke-test regression: a fault present at the first sample is a STANDING
// fault. Reporting it as a transition ("the link went down") misstates when
// it happened, and calling it "the intermittent was caught" is wrong.
func TestStandingFaultIsNotCalledIntermittent(t *testing.T) {
	w := New(Normal{})
	for i := 0; i < 4; i++ {
		w.Add(Sample{At: at(i), LinkUp: b(false), DNSOK: b(false)})
	}
	if w.Events[0].Kind != "link_down_at_start" {
		t.Errorf("first event should be a standing fault, got %q", w.Events[0].Kind)
	}
	v := w.Verdict()
	if strings.Contains(v, "intermittent WAS caught") {
		t.Errorf("standing fault reported as intermittent: %q", v)
	}
	if !strings.Contains(v, "standing fault") {
		t.Errorf("verdict does not name the standing fault: %q", v)
	}
	// And DNS must not be blamed while the link is down.
	for _, e := range w.Events {
		if e.Kind == "dns_failed" || e.Kind == "dns_failed_at_start" {
			t.Errorf("DNS blamed while the link was down: %+v", e)
		}
	}
}

// Recovery of a standing fault turns it back into a real, dateable event.
func TestStandingFaultThatRecoversIsAnEvent(t *testing.T) {
	w := New(Normal{})
	w.Add(Sample{At: at(0), LinkUp: b(false)})
	w.Add(Sample{At: at(1), LinkUp: b(true)})
	if !strings.Contains(w.Verdict(), "intermittent WAS caught") {
		t.Errorf("a fault that recovered mid-run is evidence of a flap: %q", w.Verdict())
	}
}

// A sustained condition is reported as a condition, not once per tick.
func TestSustainedConditionIsRateLimited(t *testing.T) {
	w := New(Normal{})
	for i := 0; i < 6; i++ { // 6 ticks × 10s = 50s, inside the 60s floor
		w.Add(Sample{At: at(i), WifiRSSI: f(-82)})
	}
	n := 0
	for _, e := range w.Events {
		if e.Kind == "wifi_weak" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("weak-signal condition emitted %d times, want 1", n)
	}
}
