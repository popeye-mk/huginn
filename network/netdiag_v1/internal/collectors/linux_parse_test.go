//go:build linux

package collectors

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// peakHour turns a pile of flap timestamps into "it happens around 14:00",
// which is the difference between an intermittent finding somebody can act on
// and a number they cannot.
func TestPeakHourNamesTheWorstWindow(t *testing.T) {
	// 1721312400 is inside one wall-clock hour; build the buckets directly.
	base := time.Now().Truncate(time.Hour).Unix() / 3600
	hours := map[int64]int{
		base - 3: 2,
		base - 1: 9, // the peak
		base:     4,
	}
	label, count := peakHour(hours)
	if count != 9 {
		t.Errorf("peak count = %d, want 9", count)
	}
	if label == "" {
		t.Error("peak window has no label — a count with no 'when' is not actionable")
	}
	// The label is a window, not an instant.
	if len(label) < 11 { // "HH:MM–HH:MM"
		t.Errorf("peak label %q does not look like a window", label)
	}

	// No flaps must produce no claim, not "00:00–01:00 with 0 flaps".
	if label, count := peakHour(map[int64]int{}); label != "" || count != 0 {
		t.Errorf("empty input produced (%q, %d)", label, count)
	}
	if label, count := peakHour(nil); label != "" || count != 0 {
		t.Errorf("nil input produced (%q, %d)", label, count)
	}
}

// The /proc/net/tcp address format: little-endian hex, address and port joined
// by a colon. Getting the byte order backwards silently reports connections to
// the wrong hosts.
func TestHexAddrPort(t *testing.T) {
	// 0100007F:0050 = 127.0.0.1:80
	ip, port := hexAddrPort("0100007F:0050")
	if ip != "127.0.0.1" || port != 80 {
		t.Errorf("got %s:%d, want 127.0.0.1:80", ip, port)
	}
	// 01010101:01BB = 1.1.1.1:443 — the DoH case this parser exists for.
	if ip, port := hexAddrPort("01010101:01BB"); ip != "1.1.1.1" || port != 443 {
		t.Errorf("got %s:%d, want 1.1.1.1:443", ip, port)
	}
	// Garbage must produce nothing, never a plausible-looking address.
	for _, bad := range []string{"", "nonsense", "0100007F", "ZZ:00"} {
		if ip, _ := hexAddrPort(bad); ip != "" {
			t.Errorf("hexAddrPort(%q) invented %q", bad, ip)
		}
	}
}

func TestSysReadIntReportsMissingAsMissing(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "speed"), []byte("1000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "duplex"), []byte("full\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := sysReadInt(dir, "speed"); got != 1000 {
		t.Errorf("speed = %d, want 1000", got)
	}
	if got := sysRead(dir, "duplex"); got != "full" {
		t.Errorf("duplex = %q, want full", got)
	}
	// An absent file must be negative/empty — NOT zero, because a NIC
	// reporting 0 Mbps and a NIC that cannot report are different machines.
	if got := sysReadInt(dir, "nonexistent"); got >= 0 {
		t.Errorf("absent sysfs file returned %d, which reads as a real measurement", got)
	}
	if got := sysRead(dir, "nonexistent"); got != "" {
		t.Errorf("absent sysfs file returned %q", got)
	}
	// A NIC that is down reports "-1" in speed; that is also not zero.
	if err := os.WriteFile(filepath.Join(dir, "down"), []byte("-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := sysReadInt(dir, "down"); got != -1 {
		t.Errorf("down NIC speed = %d, want -1", got)
	}
}

func TestDirExists(t *testing.T) {
	dir := t.TempDir()
	if !dirExists(dir) {
		t.Error("a real directory reported missing")
	}
	if dirExists(filepath.Join(dir, "nope")) {
		t.Error("a missing path reported present")
	}
	// A FILE named "wireless" is not a wireless directory. This is the check
	// that decides whether the machine is on Wi-Fi.
	f := filepath.Join(dir, "wireless")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if dirExists(f) {
		t.Error("a regular file was accepted as a directory")
	}
}
