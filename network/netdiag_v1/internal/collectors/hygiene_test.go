package collectors

import (
	"strings"
	"testing"
)

func TestHygieneNamesTheRiskyPortsOnly(t *testing.T) {
	// 22 (SSH) and 443 are deliberately NOT on the list: this section reports
	// exposure worth checking, not "every open port is a problem".
	data := hygieneFacts([]int{22, 443, 23, 3389, 8080}, nil, nil, nil)
	got, _ := data["hygiene_risky_listeners"].([]string)
	joined := strings.Join(got, " ")
	for _, want := range []string{"23/Telnet", "3389/RDP"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	for _, unwanted := range []string{"22/", "443/", "8080/"} {
		if strings.Contains(joined, unwanted) {
			t.Errorf("flagged a normal port %s: %v", unwanted, got)
		}
	}
	if data["hygiene_risky_listener_count"] != 2 {
		t.Errorf("count = %v, want 2", data["hygiene_risky_listener_count"])
	}
}

func TestHygienePoisoningOnlyReportsEnabled(t *testing.T) {
	data := hygieneFacts(nil, map[string]bool{"LLMNR": true, "mDNS": false, "NetBIOS-NS": true}, nil, nil)
	if data["hygiene_poisoning_exposed"] != true {
		t.Error("enabled protocols should set the exposure flag")
	}
	got, _ := data["hygiene_poisoning_protocols"].([]string)
	if len(got) != 2 || strings.Contains(strings.Join(got, " "), "mDNS") {
		t.Errorf("disabled protocol reported as exposed: %v", got)
	}

	// All off is a real, measured pass.
	clean := hygieneFacts(nil, map[string]bool{"LLMNR": false, "mDNS": false}, nil, nil)
	if clean["hygiene_poisoning_exposed"] != false {
		t.Error("all-disabled should report exposed=false, not absent")
	}
}

// Absence is never health: an unmeasurable setting must not become a false.
func TestHygieneUnmeasuredStaysAbsent(t *testing.T) {
	data := hygieneFacts(nil, nil, nil, nil)
	if _, present := data["hygiene_smb1_enabled"]; present {
		t.Error("SMB1 fact invented when it could not be read")
	}
	if _, present := data["hygiene_rdp_nla"]; present {
		t.Error("RDP NLA fact invented when it could not be read")
	}
	if _, present := data["hygiene_poisoning_exposed"]; present {
		t.Error("poisoning verdict invented with no protocols measured")
	}
}

func TestHygieneReadsExplicitBooleans(t *testing.T) {
	yes, no := true, false
	data := hygieneFacts(nil, nil, &yes, &no)
	if data["hygiene_smb1_enabled"] != true || data["hygiene_rdp_nla"] != false {
		t.Errorf("explicit values not carried through: %v", data)
	}
}
