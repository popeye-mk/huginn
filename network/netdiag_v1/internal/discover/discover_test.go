package discover

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestVendorLookup(t *testing.T) {
	if got := Vendor("52:54:00:9d:ab:45"); got != "QEMU/KVM virtual" {
		t.Errorf("KVM MAC → %q", got)
	}
	if got := Vendor("B8-27-EB-11-22-33"); got != "Raspberry Pi" { // dashes, uppercase
		t.Errorf("dash-separated MAC → %q", got)
	}
	// An unknown prefix must stay unknown rather than being guessed.
	if got := Vendor("de:ad:be:ef:00:01"); got != "" {
		t.Errorf("invented a vendor: %q", got)
	}
	if got := Vendor("junk"); got != "" {
		t.Errorf("garbage input produced %q", got)
	}
}

func TestLocallyAdministeredDetection(t *testing.T) {
	if !LocallyAdministered("de:ad:be:ef:00:01") { // 0xde has bit 1 set
		t.Error("randomised MAC not detected")
	}
	if LocallyAdministered("b8:27:eb:11:22:33") { // burned-in
		t.Error("burned-in MAC flagged as randomised")
	}
}

func TestInventorySkipsIncompleteAndMarksRoles(t *testing.T) {
	inv := FromNeighbours(map[string]string{
		"192.168.1.1":  "b8:27:eb:aa:bb:cc",
		"192.168.1.10": "52:54:00:11:22:33",
		"192.168.1.99": "00:00:00:00:00:00", // incomplete ARP entry
	}, "192.168.1.1", []string{"192.168.1.10"})

	if len(inv.Devices) != 2 {
		t.Fatalf("incomplete entry was not dropped: %+v", inv.Devices)
	}
	if !inv.Devices[0].IsGateway || inv.Devices[0].IP != "192.168.1.1" {
		t.Errorf("gateway not marked or not sorted first: %+v", inv.Devices[0])
	}
	if !inv.Devices[1].IsSelf {
		t.Errorf("own address not marked: %+v", inv.Devices[1])
	}
}

// The passive view must admit what it cannot see.
func TestPassiveRenderStatesItsLimit(t *testing.T) {
	inv := FromNeighbours(map[string]string{"10.0.0.5": "de:ad:be:ef:00:09"}, "10.0.0.1", nil)
	out := inv.Render()
	if !strings.Contains(out, "NOT a full") {
		t.Errorf("passive limit not stated:\n%s", out)
	}
	if !strings.Contains(out, "randomised MAC") {
		t.Errorf("randomised MAC not explained:\n%s", out)
	}
}

func TestNewSinceFindsArrivals(t *testing.T) {
	old := FromNeighbours(map[string]string{"10.0.0.1": "b8:27:eb:00:00:01"}, "10.0.0.1", nil)
	now := FromNeighbours(map[string]string{
		"10.0.0.1": "b8:27:eb:00:00:01",
		"10.0.0.7": "44:65:0d:aa:bb:cc", // an Amazon device appeared
	}, "10.0.0.1", nil)
	got := NewSince(old, now)
	if len(got) != 1 || got[0].Vendor != "Amazon (Echo/Fire)" {
		t.Errorf("arrival not detected correctly: %+v", got)
	}
}

// The sweep must refuse ranges that are too big, rather than trying.
func TestSweepRefusesHugeRanges(t *testing.T) {
	if _, err := HostsIn("10.0.0.0/8"); err == nil {
		t.Error("a /8 was accepted")
	}
	if _, err := HostsIn("2001:db8::/64"); err == nil {
		t.Error("an IPv6 range was accepted")
	}
	hosts, err := HostsIn("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 254 {
		t.Errorf("/24 gave %d hosts, want 254 (network and broadcast excluded)", len(hosts))
	}
	if hosts[0] != "192.168.1.1" || hosts[len(hosts)-1] != "192.168.1.254" {
		t.Errorf("range bounds wrong: %s … %s", hosts[0], hosts[len(hosts)-1])
	}
}

func TestSweepFindsRespondersAndRespectsCancel(t *testing.T) {
	ping := func(host string, _ time.Duration) (time.Duration, error) {
		if strings.HasSuffix(host, ".5") {
			return time.Millisecond, nil
		}
		return 0, context.DeadlineExceeded
	}
	alive := Sweep(context.Background(), []string{"10.0.0.1", "10.0.0.5", "10.0.0.9"}, ping, 4)
	if len(alive) != 1 || alive[0] != "10.0.0.5" {
		t.Errorf("sweep result %v", alive)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := Sweep(ctx, []string{"10.0.0.1", "10.0.0.5"}, ping, 2); len(got) != 0 {
		t.Errorf("cancelled sweep still probed: %v", got)
	}
}

// The authorization text has to actually say what it does and to whom.
func TestAuthorizationTextIsExplicit(t *testing.T) {
	txt := AuthorizationText("192.168.1.0/24", 254)
	for _, want := range []string{"AUTHORIZATION", "254", "192.168.1.0/24", "OTHER people's machines"} {
		if !strings.Contains(txt, want) {
			t.Errorf("authorization text missing %q", want)
		}
	}
}

// Field regression (Win 11, 0.9.0): the passive list showed the broadcast
// address as "randomised MAC (phones do this by default)" and counted the
// mDNS/SSDP multicast groups as unidentified devices. None of those are
// machines, and naming them as such is three wrong claims in one screen.
func TestBroadcastAndMulticastAreNotDevices(t *testing.T) {
	inv := FromNeighbours(map[string]string{
		"10.0.0.1":        "52:54:00:9d:ab:45", // the gateway — a real device
		"10.0.0.10":       "52:54:00:69:0b:92", // the DC — a real device
		"10.0.0.255":      "ff:ff:ff:ff:ff:ff", // subnet broadcast
		"255.255.255.255": "ff:ff:ff:ff:ff:ff", // all-ones broadcast
		"224.0.0.22":      "01:00:5e:00:00:16", // IGMP
		"224.0.0.251":     "01:00:5e:00:00:fb", // mDNS
		"239.255.255.250": "01:00:5e:7f:ff:fa", // SSDP
	}, "10.0.0.1", nil)

	if len(inv.Devices) != 2 {
		t.Fatalf("want 2 real devices, got %d: %+v", len(inv.Devices), inv.Devices)
	}
	out := inv.Render()
	for _, unwanted := range []string{"255.255.255.255", "224.0.0", "239.255", "ff:ff:ff"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("non-device %q still listed:\n%s", unwanted, out)
		}
	}
	// And the interpretation must not count them either.
	if strings.Contains(out, "randomised MAC") {
		t.Errorf("broadcast reported as a phone:\n%s", out)
	}
}

// Field regression (laptop, 0.9.5): the user's own router reported "unknown
// vendor" even with ieee-data installed, because its prefix is a 28-bit MA-M
// block that lives in mam.txt — not in oui.txt, which was the only file the
// parser read. Modern allocations are frequently MA-M (28-bit) or MA-S
// (36-bit), so all three registry files must be parsed and matched
// longest-prefix-first.
func TestIEEEParserHandlesAllBlockSizes(t *testing.T) {
	// Verbatim layouts from the Debian ieee-data files. Note that the MA-M and
	// MA-S files put the SHARED 24-bit OUI on the (hex) line and the actual
	// per-organisation slice on the following (base 16) line.
	oui := "00-50-56   (hex)\t\tVMware, Inc.\n" +
		"B8-27-EB   (hex)\t\tRaspberry Pi Foundation\n"

	mam := "02-1A-20   (hex)\t\tPrivate\n" +
		"F00000-FFFFFF     (base 16)\t\tAVM GmbH\n" +
		"74-1A-E0   (hex)\t\tPrivate\n" +
		"900000-9FFFFF     (base 16)\t\tSomeone Else\n"

	oui36 := "70-B3-D5   (hex)\t\tPrivate\n" +
		"1EF000-1EFFFF     (base 16)\t\tA Very Small Registrant\n"

	db := map[string]string{}
	for _, src := range []string{oui, mam, oui36} {
		parseIEEEFile(strings.NewReader(src), db)
	}
	externalOnce.Do(func() {}) // stop the lazy loader from replacing this
	externalOUI = db

	cases := []struct {
		mac, want, why string
	}{
		{"00:50:56:aa:bb:cc", "VMware virtual", "curated table beats the registry"},
		{"b8:27:eb:11:22:33", "Raspberry Pi", "curated table, 24-bit"},
		{"02:1a:20:fa:53:5f", "AVM GmbH", "28-bit MA-M slice, not the shared 'Private'"},
		{"74:1a:e0:99:00:11", "Someone Else", "a different slice of another shared OUI"},
		{"70:b3:d5:1e:f0:11", "A Very Small Registrant", "36-bit MA-S slice"},
		{"de:ad:be:ef:00:01", "", "genuinely unknown stays unknown"},
	}
	for _, c := range cases {
		if got := Vendor(c.mac); got != c.want {
			t.Errorf("Vendor(%s) = %q, want %q (%s)", c.mac, got, c.want, c.why)
		}
	}
}
