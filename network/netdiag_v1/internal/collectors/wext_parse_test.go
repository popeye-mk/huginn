//go:build linux

package collectors

import "testing"

// Channel/band decoding drives the Wi-Fi congestion findings. 6 GHz matters
// because a laptop on 6E that the tool decodes as "unknown band" silently
// drops out of the co-channel analysis — no error, just a check that quietly
// stops applying.
func TestChanBandCoversEveryBandWeClaimToSupport(t *testing.T) {
	for _, tc := range []struct {
		mhz  int
		ch   int
		band string
	}{
		{2412, 1, "2.4GHz"},
		{2437, 6, "2.4GHz"},
		{2472, 13, "2.4GHz"},
		{2484, 14, "2.4GHz"}, // Japan, and not on the arithmetic progression
		{5180, 36, "5GHz"},
		{5745, 149, "5GHz"},
		{5955, 1, "6GHz"},
		{6175, 45, "6GHz"},
	} {
		ch, band := chanBand(tc.mhz)
		if ch != tc.ch || band != tc.band {
			t.Errorf("chanBand(%d) = (%d, %q), want (%d, %q)", tc.mhz, ch, band, tc.ch, tc.band)
		}
	}

	// Out of every known band: report NOTHING rather than a plausible channel
	// number. A wrong channel feeds a wrong congestion verdict.
	for _, mhz := range []int{0, 1000, 2400, 4900, 8000} {
		if ch, band := chanBand(mhz); band != "" || ch != 0 {
			t.Errorf("chanBand(%d) = (%d, %q), want (0, \"\")", mhz, ch, band)
		}
	}
}

// WEXT reports frequency as mantissa+exponent, and hardware disagrees about
// which unit it means: some report MHz directly, others Hz.
func TestFreqMHzHandlesBothUnits(t *testing.T) {
	if got := freqMHz(2412, 0); got != 2412 {
		t.Errorf("plain MHz: got %d", got)
	}
	if got := freqMHz(2412, 6); got != 2412 { // 2412 × 10^6 Hz → MHz
		t.Errorf("Hz with exponent: got %d", got)
	}
	if got := freqMHz(5180, 0); got != 5180 {
		t.Errorf("5 GHz plain: got %d", got)
	}
}
