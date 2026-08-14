package baseline

import (
	"strings"
	"testing"
	"time"

	"netdiag/internal/schema"
)

func TestDiffDetectsTheClassics(t *testing.T) {
	good := map[string]any{
		"gateway_mac": "aa:bb:cc:dd:ee:ff", "gateway_ip": "192.168.1.1",
		"dhcp_server": "192.168.1.1", "dns_servers": []string{"192.168.1.1"},
		"path_mtu": 1500, "upstream_rtt_avg_ms": 12.0, "upstream_loss_pct": 0,
		"proxy_configured": false, "wifi_signal_dbm": -40.0,
	}
	bad := map[string]any{
		"gateway_mac": "11:22:33:44:55:66", // ARP-spoof / replaced router
		"gateway_ip":  "192.168.1.1",
		"dhcp_server": "192.168.1.99", // rogue DHCP
		"dns_servers": []string{"8.8.8.8"},
		"path_mtu":    1400, "upstream_rtt_avg_ms": 80.0, "upstream_loss_pct": 15,
		"proxy_configured": true, "wifi_signal_dbm": -70.0,
	}
	changes := Diff(good, bad)
	wantFields := []string{"gateway_mac", "dhcp_server", "dns_servers", "path_mtu",
		"proxy_configured", "upstream_rtt_avg_ms", "upstream_loss_pct", "wifi_signal_dbm"}
	got := map[string]Change{}
	for _, c := range changes {
		got[c.Field] = c
	}
	for _, f := range wantFields {
		if _, ok := got[f]; !ok {
			t.Errorf("diff missed %s", f)
		}
	}
	if _, ok := got["gateway_ip"]; ok {
		t.Error("unchanged gateway_ip flagged")
	}
	// Ranked: criticals first.
	if len(changes) > 0 && changes[0].Severity != "critical" {
		t.Errorf("top change is %s, want critical first", changes[0].Severity)
	}
}

func TestDiffNoFalseDrift(t *testing.T) {
	same := map[string]any{
		"gateway_mac": "aa:bb:cc:dd:ee:ff", "upstream_rtt_avg_ms": 12.0,
		"upstream_loss_pct": 0, "dns_servers": []string{"1.1.1.1"},
	}
	// Small wobble is not drift.
	wobble := map[string]any{
		"gateway_mac": "aa:bb:cc:dd:ee:ff", "upstream_rtt_avg_ms": 14.5,
		"upstream_loss_pct": 0, "dns_servers": []string{"1.1.1.1"},
	}
	if c := Diff(same, wobble); len(c) != 0 {
		t.Errorf("wobble flagged as drift: %+v", c)
	}
	// Absence is never drift: a fact unmeasured on one side must not fire
	// the regression comparators.
	if c := Diff(map[string]any{}, map[string]any{"upstream_loss_pct": 100}); len(c) != 0 {
		t.Errorf("one-sided numeric flagged: %+v", c)
	}
}

func TestDiffImprovementIsNotDrift(t *testing.T) {
	good := map[string]any{"upstream_rtt_avg_ms": 80.0, "upstream_loss_pct": 20}
	better := map[string]any{"upstream_rtt_avg_ms": 10.0, "upstream_loss_pct": 0}
	if c := Diff(good, better); len(c) != 0 {
		t.Errorf("improvement flagged as drift: %+v", c)
	}
}

func TestLocationKeyPrefersGatewayMAC(t *testing.T) {
	k := LocationKey(map[string]any{"gateway_mac": "aa:bb:cc:dd:ee:ff", "wifi_ssid": "Home"})
	if k != "aa_bb_cc_dd_ee_ff" {
		t.Errorf("key = %q", k)
	}
	if LocationKey(map[string]any{"wifi_ssid": "Cafe WiFi!"}) != "Cafe_WiFi_" {
		t.Errorf("ssid fallback wrong: %q", LocationKey(map[string]any{"wifi_ssid": "Cafe WiFi!"}))
	}
	if LocationKey(map[string]any{}) != "unknown-location" {
		t.Error("empty facts key wrong")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	t.Setenv("NETDIAG_BASELINES", t.TempDir())
	snap := &schema.Snapshot{
		SchemaVersion: schema.SchemaVersion, Tool: "netdiag", CollectedAt: time.Now(),
		Collectors: map[string]schema.CollectorResult{
			"routing": {Status: schema.StatusOK, Data: map[string]any{"gateway_ip": "10.0.0.1"}},
			"neigh":   {Status: schema.StatusOK, Data: map[string]any{"gateway_mac": "aa:bb:cc:dd:ee:ff"}},
		},
	}
	facts := snap.Facts()
	key, err := Save(snap, facts)
	if err != nil {
		t.Fatal(err)
	}
	loaded, savedAt, key2, err := Load(facts)
	if err != nil || key != key2 || savedAt.IsZero() {
		t.Fatalf("load: %v (key %q vs %q)", err, key, key2)
	}
	if loaded.Facts()["gateway_ip"] != "10.0.0.1" {
		t.Errorf("round-trip lost facts: %v", loaded.Facts())
	}
}

// The broken moment must still find the baseline: saved with a live gateway
// (MAC known), loaded with a dead one (MAC fact gone, only gateway_ip left).
func TestLoadFallsBackWhenGatewayDies(t *testing.T) {
	t.Setenv("NETDIAG_BASELINES", t.TempDir())
	snap := &schema.Snapshot{
		SchemaVersion: schema.SchemaVersion,
		Collectors: map[string]schema.CollectorResult{
			"routing": {Status: schema.StatusOK, Data: map[string]any{"gateway_ip": "10.0.0.1"}},
			"neigh":   {Status: schema.StatusOK, Data: map[string]any{"gateway_mac": "aa:bb:cc:dd:ee:ff"}},
		},
	}
	if _, err := Save(snap, snap.Facts()); err != nil {
		t.Fatal(err)
	}
	brokenFacts := map[string]any{"gateway_ip": "10.0.0.1"} // no MAC — gateway dead
	if _, _, _, err := Load(brokenFacts); err != nil {
		t.Fatalf("baseline unfindable in the broken state: %v", err)
	}
}

func TestRenderRanksAndAdmitsIgnores(t *testing.T) {
	out := Render(Diff(
		map[string]any{"gateway_mac": "aa:bb:cc:dd:ee:ff", "wifi_channel": 6},
		map[string]any{"gateway_mac": "11:22:33:44:55:66", "wifi_channel": 11},
	), "test")
	if !strings.Contains(out, "Start with #1 (gateway_mac)") {
		t.Errorf("ranked verdict missing:\n%s", out)
	}
	if !strings.Contains(out, "Deliberately ignored") {
		t.Error("honest-ignores line missing")
	}
}
