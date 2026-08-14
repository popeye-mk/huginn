//go:build linux

package collectors

import (
	"fmt"
	"syscall"
	"unsafe"
)

// Wireless-extensions ioctls: SSID/BSSID/frequency/bitrate without nl80211.
// WEXT is legacy but every mainline driver still answers it through the
// cfg80211 compat layer — which makes it the honest zero-dependency middle
// ground until a real generic-netlink nl80211 client lands. Each call
// degrades to "absent fact" on any error; nothing is guessed.

const (
	siocgiwessid = 0x8B1B
	siocgiwap    = 0x8B15
	siocgiwfreq  = 0x8B05
	siocgiwrate  = 0x8B21
	iwEssidMax   = 32
)

// iwreq layouts (64-bit): 16-byte ifname + 16-byte union.
type iwPoint struct {
	Pointer uintptr
	Length  uint16
	Flags   uint16
	_       [4]byte
}

type iwFreq struct {
	M     int32
	E     int16
	I     uint8
	Flags uint8
	_     [8]byte
}

type iwParam struct {
	Value    int32
	Fixed    uint8
	Disabled uint8
	Flags    uint16
	_        [8]byte
}

type iwreqPoint struct {
	Name [16]byte
	U    iwPoint
}

type iwreqFreq struct {
	Name [16]byte
	U    iwFreq
}

type iwreqParam struct {
	Name [16]byte
	U    iwParam
}

type iwreqSockaddr struct {
	Name   [16]byte
	Family uint16
	Data   [14]byte
}

// wextInfo enriches the wifi facts for one interface. All best-effort.
func wextInfo(ifname string, data map[string]any) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return
	}
	defer syscall.Close(fd)

	// SSID
	var essid [iwEssidMax]byte
	var reqP iwreqPoint
	copy(reqP.Name[:], ifname)
	reqP.U = iwPoint{Pointer: uintptr(unsafe.Pointer(&essid[0])), Length: iwEssidMax}
	if ioctl(fd, siocgiwessid, unsafe.Pointer(&reqP)) == nil && reqP.U.Length > 0 {
		n := int(reqP.U.Length)
		if n > iwEssidMax {
			n = iwEssidMax
		}
		if s := string(essid[:n]); s != "" {
			data["wifi_ssid"] = s
		}
	}

	// BSSID
	var reqS iwreqSockaddr
	copy(reqS.Name[:], ifname)
	if ioctl(fd, siocgiwap, unsafe.Pointer(&reqS)) == nil {
		mac := reqS.Data[:6]
		zero := true
		for _, b := range mac {
			if b != 0 {
				zero = false
			}
		}
		if !zero {
			data["wifi_bssid"] = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
				mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
		}
	}

	// Frequency → MHz, channel, band
	var reqF iwreqFreq
	copy(reqF.Name[:], ifname)
	if ioctl(fd, siocgiwfreq, unsafe.Pointer(&reqF)) == nil && reqF.U.M > 0 {
		mhz := freqMHz(reqF.U.M, reqF.U.E)
		if mhz > 1000 {
			data["wifi_freq_mhz"] = mhz
			if ch, band := chanBand(mhz); ch > 0 {
				data["wifi_channel"] = ch
				data["wifi_band"] = band
			}
		} else if mhz > 0 { // some drivers report the channel number directly
			data["wifi_channel"] = mhz
		}
	}

	// PHY rate
	var reqR iwreqParam
	copy(reqR.Name[:], ifname)
	if ioctl(fd, siocgiwrate, unsafe.Pointer(&reqR)) == nil && reqR.U.Value > 0 {
		data["wifi_phy_rate_mbps"] = int(reqR.U.Value) / 1_000_000
	}
}

func ioctl(fd int, cmd uintptr, arg unsafe.Pointer) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), cmd, uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}

func freqMHz(m int32, e int16) int {
	v := float64(m)
	for i := int16(0); i < e; i++ {
		v *= 10
	}
	if v > 1e6 { // Hz → MHz
		return int(v / 1e6)
	}
	return int(v)
}

func chanBand(mhz int) (int, string) {
	switch {
	case mhz == 2484:
		return 14, "2.4GHz"
	case mhz >= 2412 && mhz <= 2472:
		return (mhz-2407)/5 + 0, "2.4GHz"
	case mhz >= 5150 && mhz <= 5895:
		return (mhz - 5000) / 5, "5GHz"
	case mhz >= 5955 && mhz <= 7115:
		return (mhz - 5950) / 5, "6GHz"
	}
	return 0, ""
}
