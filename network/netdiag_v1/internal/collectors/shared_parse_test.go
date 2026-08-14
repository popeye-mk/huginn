package collectors

import (
	"os"
	"path/filepath"
	"testing"
)

// These functions were already pure; they simply had no tests. Each one turns
// raw evidence into a claim the tool then makes out loud, and two of them
// produced real findings in the field.

// The hosts file found genuine overrides on an unplanted machine. Its job is
// to report DELIBERATE pinning while ignoring the boilerplate every distro
// ships — a parser that flags `127.0.0.1 localhost` cries wolf on every
// machine and gets ignored on the one that matters.
func TestHostsOverridesIgnoresBoilerplate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	const hosts = `# Standard host addresses
127.0.0.1	localhost
127.0.1.1	this-machine.localdomain this-machine
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

# The interesting lines: someone pinned these by hand
10.0.0.55	fileserver.corp.local fileserver
192.168.1.240	printer
203.0.113.10	updates.vendor.example
`
	if err := os.WriteFile(path, []byte(hosts), 0o600); err != nil {
		t.Fatal(err)
	}
	got := hostsOverrides(path)
	if len(got) != 3 {
		t.Fatalf("got %d overrides, want 3:\n%v", len(got), got)
	}
	for _, want := range []string{"fileserver", "printer", "updates.vendor.example"} {
		var found bool
		for _, line := range got {
			if contains(line, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("real override %q was not reported", want)
		}
	}
	for _, noise := range got {
		if contains(noise, "localhost") || contains(noise, "ip6-") {
			t.Errorf("boilerplate reported as an override: %q", noise)
		}
	}

	// A missing hosts file is not an empty hosts file, but returning nil for
	// both is safe here: nil means "nothing to report", and the collector
	// reports its own read failure separately.
	if got := hostsOverrides(filepath.Join(dir, "nope")); got != nil {
		t.Errorf("missing file produced %v", got)
	}
}

// Split-brain DNS: two resolvers answering differently for one name is the
// finding. An ERRORING resolver is a different finding, and counting it as
// disagreement would blame DNS inconsistency for a dead server.
func TestResolverDisagreementIgnoresErrors(t *testing.T) {
	same := map[string][]string{
		"192.168.1.1": {"10.0.0.5"},
		"1.1.1.1":     {"10.0.0.5"},
	}
	if disagree(same) {
		t.Error("identical answers reported as disagreement")
	}

	differ := map[string][]string{
		"192.168.1.1": {"10.0.0.5"},
		"1.1.1.1":     {"203.0.113.9"},
	}
	if !disagree(differ) {
		t.Error("genuinely different answers were not reported")
	}

	withError := map[string][]string{
		"192.168.1.1": {"10.0.0.5"},
		"1.1.1.1":     {"error: timeout"},
	}
	if disagree(withError) {
		t.Error("a dead resolver was reported as a disagreement — wrong finding, wrong fix")
	}

	if disagree(map[string][]string{}) || disagree(map[string][]string{"a": {"1.2.3.4"}}) {
		t.Error("fewer than two answers cannot disagree")
	}
}

func TestProxyHostPortStripsCredentials(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"http://proxy.corp.local:3128", "proxy.corp.local:3128"},
		{"http://user:secret@proxy.corp.local:3128", "proxy.corp.local:3128"},
		{"proxy.corp.local:3128", "proxy.corp.local:3128"},
		{"", ""},
	} {
		if got := proxyHostPort(tc.in); got != tc.want {
			t.Errorf("proxyHostPort(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if contains(proxyHostPort(tc.in), "secret") {
			t.Errorf("a proxy password survived into a fact: %q", proxyHostPort(tc.in))
		}
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// Bug #24 regression, kept separate because it is the whole reason the
// boilerplate filter was rewritten: this exact block ships in /etc/hosts on
// Debian, Ubuntu, Zorin, Fedora and friends, and every line of it used to be
// reported as a deliberate override.
func TestStockDistroHostsFileProducesNoFindings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	const stock = `127.0.0.1	localhost
127.0.1.1	zorin

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
`
	if err := os.WriteFile(path, []byte(stock), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := hostsOverrides(path); len(got) != 0 {
		t.Errorf("a stock hosts file produced %d override(s) — this finding would fire on "+
			"every Linux machine and be learned as noise:\n%v", len(got), got)
	}
}

// …and the filter must not have gone too far the other way. A real override
// that happens to use an IPv6 address is still an override.
func TestRealIPv6OverrideIsStillReported(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	const hosts = `::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
2001:db8::42	fileserver.corp.local
`
	if err := os.WriteFile(path, []byte(hosts), 0o600); err != nil {
		t.Fatal(err)
	}
	got := hostsOverrides(path)
	if len(got) != 1 {
		t.Fatalf("got %d, want the one real override:\n%v", len(got), got)
	}
	if !contains(got[0], "fileserver.corp.local") {
		t.Errorf("wrong line reported: %q", got[0])
	}
}

// hygieneFacts turns raw posture readings into the §12 facts. The pointers
// matter: nil means "not measured", and collapsing that to false would report
// SMB1 as disabled on a machine nobody asked.
func TestHygieneFactsKeepUnmeasuredUnmeasured(t *testing.T) {
	yes, no := true, false

	full := hygieneFacts([]int{23, 445}, map[string]bool{"LLMNR": true, "mDNS": false}, &yes, &no)
	if full["hygiene_risky_listener_count"] != 2 {
		t.Errorf("risky listener count = %v", full["hygiene_risky_listener_count"])
	}
	if full["hygiene_smb1_enabled"] != true {
		t.Errorf("smb1 = %v", full["hygiene_smb1_enabled"])
	}
	if full["hygiene_rdp_nla"] != false {
		t.Errorf("rdp nla = %v", full["hygiene_rdp_nla"])
	}
	if full["hygiene_poisoning_exposed"] != true {
		t.Errorf("one enabled poisoning protocol should expose: %v", full["hygiene_poisoning_exposed"])
	}

	// Nothing measured: the keys must be ABSENT, not present-and-false.
	// Present-and-false is a claim; absent is the truth.
	none := hygieneFacts(nil, nil, nil, nil)
	for _, k := range []string{"hygiene_smb1_enabled", "hygiene_rdp_nla"} {
		if v, present := none[k]; present {
			t.Errorf("%s reported as %v when nothing was measured", k, v)
		}
	}

	// All poisoning protocols off is a real, measured "not exposed".
	off := hygieneFacts(nil, map[string]bool{"LLMNR": false, "NetBIOS-NS": false}, nil, nil)
	if off["hygiene_poisoning_exposed"] != false {
		t.Errorf("all protocols off should be measured-not-exposed, got %v",
			off["hygiene_poisoning_exposed"])
	}
}
