//go:build windows

package collectors

// Thin wrappers over iphlpapi.dll via the stdlib's syscall.NewLazyDLL —
// the zero-dependency way to reach the Windows IP Helper API (§17.4).
// Everything degrades to absent facts / honest skips on API failure.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"
)

var (
	iphlpapi           = syscall.NewLazyDLL("iphlpapi.dll")
	procIcmpCreateFile = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseFile  = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho   = iphlpapi.NewProc("IcmpSendEcho")
	procGetIpFwdTable  = iphlpapi.NewProc("GetIpForwardTable")
	procGetIpNetTable  = iphlpapi.NewProc("GetIpNetTable")
	procGetTcpTable    = iphlpapi.NewProc("GetTcpTable")
	procGetUdpTable    = iphlpapi.NewProc("GetUdpTable")
	procGetTcpStats    = iphlpapi.NewProc("GetTcpStatistics")
	procGetNetParams   = iphlpapi.NewProc("GetNetworkParams")
	procGetAdaptInfo   = iphlpapi.NewProc("GetAdaptersInfo")
	procGetIfTable     = iphlpapi.NewProc("GetIfTable")
)

// ------------------------------------------------------------------ ICMP

// icmpEchoWin: one echo via IcmpSendEcho — unprivileged on Windows.
func icmpEchoWin(target string, timeout time.Duration) (time.Duration, error) {
	ip := net.ParseIP(target).To4()
	if ip == nil {
		return 0, errors.New("not an IPv4 target")
	}
	h, _, _ := procIcmpCreateFile.Call()
	if h == uintptr(^uintptr(0)) { // INVALID_HANDLE_VALUE
		return 0, errors.New("IcmpCreateFile failed")
	}
	defer procIcmpCloseFile.Call(h)

	payload := []byte("netdiag0")
	reply := make([]byte, 1024)
	addr := binary.LittleEndian.Uint32(ip)
	start := time.Now()
	n, _, _ := procIcmpSendEcho.Call(h, uintptr(addr),
		uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)),
		0, uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)),
		uintptr(timeout.Milliseconds()))
	if n == 0 {
		return 0, errors.New("no echo reply")
	}
	// ICMP_ECHO_REPLY.Status at offset 4; 0 = IP_SUCCESS.
	if status := binary.LittleEndian.Uint32(reply[4:]); status != 0 {
		return 0, fmt.Errorf("echo status %d", status)
	}
	// RoundTripTime at offset 8 (ms) — prefer the kernel's own number.
	rtt := time.Duration(binary.LittleEndian.Uint32(reply[8:])) * time.Millisecond
	if rtt == 0 {
		rtt = time.Since(start)
	}
	return rtt, nil
}

// --------------------------------------------------------- table helpers

// getSizedTable calls a GetXxxTable(buf, &size, order) style API with the
// grow-on-ERROR_INSUFFICIENT_BUFFER dance and returns the raw buffer.
func getSizedTable(p *syscall.LazyProc) ([]byte, error) {
	var size uint32
	p.Call(0, uintptr(unsafe.Pointer(&size)), 1)
	if size == 0 {
		return nil, errors.New(p.Name + ": zero size")
	}
	buf := make([]byte, size)
	r, _, _ := p.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1)
	if r != 0 {
		return nil, fmt.Errorf("%s: error %d", p.Name, r)
	}
	return buf, nil
}

func leU32(b []byte, off int) uint32 { return binary.LittleEndian.Uint32(b[off:]) }

func ipv4FromLE(v uint32) string {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, v)
	return ip.String()
}

// ---------------------------------------------------------- route table

type winRoute struct {
	dest, mask, nextHop string
	ifIndex             int
	metric              int
}

// MIB_IPFORWARDROW: 14 DWORDs (56 bytes).
func winRouteTable() ([]winRoute, error) {
	buf, err := getSizedTable(procGetIpFwdTable)
	if err != nil {
		return nil, err
	}
	n := int(leU32(buf, 0))
	rows := make([]winRoute, 0, n)
	for i := 0; i < n; i++ {
		off := 4 + i*56
		if off+56 > len(buf) {
			break
		}
		rows = append(rows, winRoute{
			dest:    ipv4FromLE(leU32(buf, off)),
			mask:    ipv4FromLE(leU32(buf, off+4)),
			nextHop: ipv4FromLE(leU32(buf, off+12)),
			ifIndex: int(leU32(buf, off+16)),
			metric:  int(leU32(buf, off+36)),
		})
	}
	return rows, nil
}

// ------------------------------------------------------------ ARP table

type winArp struct {
	ip, mac string
	typ     int // 1 other, 2 invalid, 3 dynamic, 4 static
}

// MIB_IPNETROW: Index, PhysAddrLen, PhysAddr[8], Addr, Type = 24 bytes.
func winArpTable() ([]winArp, error) {
	buf, err := getSizedTable(procGetIpNetTable)
	if err != nil {
		return nil, err
	}
	n := int(leU32(buf, 0))
	rows := make([]winArp, 0, n)
	for i := 0; i < n; i++ {
		off := 4 + i*24
		if off+24 > len(buf) {
			break
		}
		macLen := int(leU32(buf, off+4))
		mac := ""
		if macLen >= 6 {
			m := buf[off+8 : off+14]
			mac = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
		}
		rows = append(rows, winArp{
			ip:  ipv4FromLE(leU32(buf, off+16)),
			mac: mac,
			typ: int(leU32(buf, off+20)),
		})
	}
	return rows, nil
}

// ------------------------------------------------------------ TCP / UDP

type winTCPConn struct {
	state         int // 2 listen, 5 estab, 11 time-wait
	localAddr     string
	localPort     int
	remoteAddr    string
	remotePort    int
	localLoopback bool
}

// MIB_TCPROW: 5 DWORDs; ports are big-endian in the low 16 bits.
func winTCPTable() ([]winTCPConn, error) {
	buf, err := getSizedTable(procGetTcpTable)
	if err != nil {
		return nil, err
	}
	n := int(leU32(buf, 0))
	rows := make([]winTCPConn, 0, n)
	for i := 0; i < n; i++ {
		off := 4 + i*20
		if off+20 > len(buf) {
			break
		}
		la := leU32(buf, off+4)
		rows = append(rows, winTCPConn{
			state:         int(leU32(buf, off)),
			localAddr:     ipv4FromLE(la),
			localPort:     tcpPort(leU32(buf, off+8)),
			remoteAddr:    ipv4FromLE(leU32(buf, off+12)),
			remotePort:    tcpPort(leU32(buf, off+16)),
			localLoopback: la&0xFF == 127,
		})
	}
	return rows, nil
}

func winUDPCount() int {
	buf, err := getSizedTable(procGetUdpTable)
	if err != nil {
		return -1
	}
	return int(leU32(buf, 0))
}

func tcpPort(v uint32) int { return int(v>>8&0xFF | v<<8&0xFF00) }

// MIB_TCPSTATS: 15 DWORDs.
type winTCPStats struct {
	attemptFails, estabResets, outSegs, retransSegs, outRsts int64
}

func winTCPStatistics() (winTCPStats, error) {
	buf := make([]byte, 60)
	r, _, _ := procGetTcpStats.Call(uintptr(unsafe.Pointer(&buf[0])))
	if r != 0 {
		return winTCPStats{}, fmt.Errorf("GetTcpStatistics: %d", r)
	}
	return winTCPStats{
		attemptFails: int64(leU32(buf, 24)),
		estabResets:  int64(leU32(buf, 28)),
		outSegs:      int64(leU32(buf, 44)),
		retransSegs:  int64(leU32(buf, 48)),
		outRsts:      int64(leU32(buf, 56)),
	}, nil
}

// -------------------------------------------------- DNS servers / DHCP

// FIXED_INFO from GetNetworkParams: HostName[132], DomainName[132],
// CurrentDnsServer ptr, DnsServerList IP_ADDR_STRING, ...
// IP_ADDR_STRING: Next ptr, IpAddress[16], IpMask[16], Context DWORD.
func winDNSServers() []string {
	var size uint32
	procGetNetParams.Call(0, uintptr(unsafe.Pointer(&size)))
	if size == 0 {
		return nil
	}
	buf := make([]byte, size)
	if r, _, _ := procGetNetParams.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size))); r != 0 {
		return nil
	}
	// DnsServerList starts at 132+132+8 (ptr, amd64) = 272.
	return walkIPAddrString((*ipAddrString)(unsafe.Pointer(&buf[272])))
}

type ipAddrString struct {
	Next    *ipAddrString
	Addr    [16]byte
	Mask    [16]byte
	Context uint32
	_       [4]byte
}

func walkIPAddrString(node *ipAddrString) []string {
	var out []string
	for ; node != nil; node = node.Next {
		s := cstr(node.Addr[:])
		if s != "" && s != "0.0.0.0" {
			out = append(out, s)
		}
		if len(out) > 8 {
			break
		}
	}
	return out
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// IP_ADAPTER_INFO (amd64): Next ptr(8), ComboIndex(4), AdapterName[260],
// Description[132], AddressLength(4), Address[8], Index(4), Type(4),
// DhcpEnabled(4), CurrentIpAddress ptr(8), IpAddressList(40),
// GatewayList(40), DhcpServer(40), HaveWins(4), PrimaryWins(40),
// SecondaryWins(40), LeaseObtained(8), LeaseExpires(8).
func winDHCPInfo() (server string, hoursLeft float64, ok bool) {
	var size uint32
	procGetAdaptInfo.Call(0, uintptr(unsafe.Pointer(&size)))
	if size == 0 {
		return "", 0, false
	}
	buf := make([]byte, size)
	if r, _, _ := procGetAdaptInfo.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size))); r != 0 {
		return "", 0, false
	}
	base := uintptr(unsafe.Pointer(&buf[0]))
	const (
		offDhcpEnabled  = 8 + 4 + 260 + 132 + 4 + 8 + 4 + 4    // = 424
		offDhcpServer   = offDhcpEnabled + 4 + 8 + 40 + 40     // 516
		offLeaseExpires = offDhcpServer + 40 + 4 + 4 + 40 + 40 // 644 (HaveWins padded)
	)
	_ = base
	for off := 0; off+offLeaseExpires+8 <= len(buf); {
		if leU32(buf, off+offDhcpEnabled) == 1 {
			srv := cstr(buf[off+offDhcpServer+8 : off+offDhcpServer+24]) // skip Next ptr
			if srv != "" && srv != "0.0.0.0" {
				expires := int64(binary.LittleEndian.Uint64(buf[off+offLeaseExpires:]))
				h := 0.0
				if expires > 0 {
					h = time.Until(time.Unix(expires, 0)).Hours()
				}
				return srv, h, true
			}
		}
		next := binary.LittleEndian.Uint64(buf[off:])
		if next == 0 {
			break
		}
		delta := int(next - uint64(uintptr(unsafe.Pointer(&buf[off]))))
		if delta <= 0 || off+delta >= len(buf) {
			break
		}
		off += delta
	}
	return "", 0, false
}

// ------------------------------------------------------- interface table

type winIfRow struct {
	index, mtu, speedMbps int
	ifType                int
	inErrors, outErrors   int64
	inPackets, outPackets int64
	operStatus            int
}

// MIB_IFROW: wszName[256]WCHAR=512, then DWORDs from 512.
func winIfTable() ([]winIfRow, error) {
	buf, err := getSizedTable(procGetIfTable)
	if err != nil {
		return nil, err
	}
	n := int(leU32(buf, 0))
	const rowSize = 512 + 40*4 + 256 + 4 // name + 40 dwords... use documented 860-byte row
	_ = rowSize
	// MIB_IFROW is 864 bytes on amd64 (with alignment).
	const sz = 864
	rows := make([]winIfRow, 0, n)
	for i := 0; i < n; i++ {
		off := 8 + i*sz // dwNumEntries padded to 8 on amd64
		if off+sz > len(buf) {
			break
		}
		rows = append(rows, winIfRow{
			index: int(leU32(buf, off+512)),
			// dwType sits between dwIndex and dwMtu. 6 = ethernet,
			// 71 = IEEE80211. Same numeric discipline as everywhere else on
			// Windows: never the adapter's display name, which is localised
			// and renameable by the user.
			ifType:     int(leU32(buf, off+516)),
			mtu:        int(leU32(buf, off+520)),
			speedMbps:  int(leU32(buf, off+524) / 1_000_000),
			operStatus: int(leU32(buf, off+544)),
			inPackets:  int64(leU32(buf, off+556)) + int64(leU32(buf, off+560)),
			inErrors:   int64(leU32(buf, off+568)),
			outPackets: int64(leU32(buf, off+580)) + int64(leU32(buf, off+584)),
			outErrors:  int64(leU32(buf, off+592)),
		})
	}
	return rows, nil
}
