//go:build linux

package collectors

import "testing"

func TestParseKVWithSpacedKeys(t *testing.T) {
	kv := parseKV(`bssid=aa:bb:cc:dd:ee:ff
ssid=CorpNet
key_mgmt=WPA2-PSK/WPA-EAP
Supplicant PAE state=AUTHENTICATED
suppPortStatus=Authorized
EAP state=SUCCESS
wpa_state=COMPLETED`)
	if kv["ssid"] != "CorpNet" || kv["Supplicant PAE state"] != "AUTHENTICATED" ||
		kv["EAP state"] != "SUCCESS" {
		t.Errorf("parseKV wrong: %v", kv)
	}
}

func TestAddDot1xFacts(t *testing.T) {
	data := map[string]any{}
	addDot1xFacts(parseKV("key_mgmt=WPA2-EAP\nEAP state=FAILURE\nSupplicant PAE state=HELD"), data)
	if data["dot1x_active"] != true || data["dot1x_eap_state"] != "FAILURE" ||
		data["dot1x_pae_state"] != "HELD" {
		t.Errorf("dot1x facts wrong: %v", data)
	}
	psk := map[string]any{}
	addDot1xFacts(parseKV("key_mgmt=WPA2-PSK"), psk)
	if psk["dot1x_active"] != false {
		t.Errorf("PSK network marked as 802.1X: %v", psk)
	}
	if _, present := psk["dot1x_eap_state"]; present {
		t.Error("EAP state invented for a PSK network")
	}
}

func TestParseScanResults(t *testing.T) {
	scan := "bssid / frequency / signal level / flags / ssid\n" +
		"aa:aa:aa:aa:aa:aa\t2437\t-45\t[WPA2-PSK-CCMP][ESS]\tHomeNet\n" + // our own BSS
		"bb:bb:bb:bb:bb:bb\t2437\t-60\t[WPA2-PSK-CCMP][ESS]\tNeighbor1\n" + // co-channel
		"cc:cc:cc:cc:cc:cc\t2442\t-70\t[WPA2-PSK-CCMP][ESS]\tNeighbor2\n" + // adjacent
		"dd:dd:dd:dd:dd:dd\t2437\t-72\t[WPA2-PSK-CCMP][ESS]\tHomeNet\n" + // roam candidate (also co-channel)
		"ee:ee:ee:ee:ee:ee\t5180\t-80\t[WPA2-PSK-CCMP][ESS]\tFarAway\n" // different band
	st := parseScanResults(scan, "aa:aa:aa:aa:aa:aa", "HomeNet", 2437)
	if st.neighbors != 4 {
		t.Errorf("neighbors = %d, want 4", st.neighbors)
	}
	if st.coChannel != 2 {
		t.Errorf("coChannel = %d, want 2", st.coChannel)
	}
	if st.adjacent != 1 {
		t.Errorf("adjacent = %d, want 1", st.adjacent)
	}
	if st.sameSSID != 1 {
		t.Errorf("sameSSID = %d, want 1", st.sameSSID)
	}
}
