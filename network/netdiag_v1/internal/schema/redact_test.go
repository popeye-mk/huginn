package schema

import (
	"strings"
	"testing"
	"time"
)

// Redaction is a security control (§4.3): a snapshot field with no recorded
// redaction decision fails this test, and --anon must actually strip what it
// promises to strip.
func TestRedactionPolicyDecisionsAreValid(t *testing.T) {
	valid := map[string]bool{Keep: true, MaskIP: true, MaskMAC: true, Drop: true}
	for k, v := range RedactionPolicy {
		if !valid[v] {
			t.Errorf("fact %s: unknown redaction action %q", k, v)
		}
	}
}

func TestRedactMasksAndDrops(t *testing.T) {
	snap := &Snapshot{
		Hostname: "franks-laptop",
		Collectors: map[string]CollectorResult{
			"routing": {Status: StatusOK, Data: map[string]any{
				"gateway_ip":            "203.0.113.7", // public → masked
				"default_route_present": true,          // keep
			}},
			"addressing": {Status: StatusOK, Data: map[string]any{
				"ipv4_addresses": []string{"192.168.1.10", "203.0.113.9"},
			}},
			"neigh": {Status: StatusOK, Data: map[string]any{
				"gateway_mac": "aa:bb:cc:dd:ee:ff",
			}},
			"dns": {Status: StatusOK, Data: map[string]any{
				"dns_error": "lookup foo on 10.0.0.1: timeout", // drop
			}},
			"mystery": {Status: StatusOK, Data: map[string]any{
				"totally_new_unclassified_fact": "secret", // unclassified → drop
			}},
		},
		CollectedAt: time.Now(),
	}
	snap.Redact()

	if snap.Hostname == "franks-laptop" {
		t.Error("hostname not redacted")
	}
	if got := snap.Collectors["routing"].Data["gateway_ip"]; got != "203.x.x.x" {
		t.Errorf("public gateway not masked: %v", got)
	}
	if got := snap.Collectors["routing"].Data["default_route_present"]; got != true {
		t.Errorf("keep field was altered: %v", got)
	}
	addrs, _ := snap.Collectors["addressing"].Data["ipv4_addresses"].([]string)
	if len(addrs) != 2 || addrs[0] != "192.168.1.10" || addrs[1] != "203.x.x.x" {
		t.Errorf("address list masking wrong: %v", addrs)
	}
	mac, _ := snap.Collectors["neigh"].Data["gateway_mac"].(string)
	if !strings.HasPrefix(mac, "aa:bb:cc:") || strings.Contains(mac, "dd") {
		t.Errorf("MAC not OUI-masked: %v", mac)
	}
	if _, present := snap.Collectors["dns"].Data["dns_error"]; present {
		t.Error("drop field survived")
	}
	if _, present := snap.Collectors["mystery"].Data["totally_new_unclassified_fact"]; present {
		t.Error("unclassified field survived — the safe default must be drop")
	}
}
