//go:build linux

package collectors

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"syscall"
	"time"
)

// icmpEcho hand-rolls one ICMP echo request/reply with the standard library
// only — no x/net dependency, so the tool stays a zero-dependency build.
// It tries the unprivileged SOCK_DGRAM ICMP socket first (available when
// net.ipv4.ping_group_range allows), then falls back to SOCK_RAW (root).
func icmpEcho(target string, seq int, timeout time.Duration) (time.Duration, error) {
	dst := net.ParseIP(target).To4()
	if dst == nil {
		return 0, errors.New("not an IPv4 target")
	}
	fd, raw, err := icmpSocket()
	if err != nil {
		return 0, err
	}
	defer syscall.Close(fd)

	// Build echo request: type 8, code 0, checksum, id, seq, payload.
	pkt := make([]byte, 16)
	pkt[0] = 8
	id := uint16(os.Getpid() & 0xffff)
	binary.BigEndian.PutUint16(pkt[4:], id)
	binary.BigEndian.PutUint16(pkt[6:], uint16(seq))
	copy(pkt[8:], "netdiag0")
	binary.BigEndian.PutUint16(pkt[2:], icmpChecksum(pkt))

	sa := &syscall.SockaddrInet4{}
	copy(sa.Addr[:], dst)

	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	start := time.Now()
	if err := syscall.Sendto(fd, pkt, 0, sa); err != nil {
		return 0, err
	}
	buf := make([]byte, 1500)
	deadline := start.Add(timeout)
	for time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return 0, err // includes EAGAIN on timeout
		}
		payload := buf[:n]
		if raw && n >= 20 {
			payload = payload[(payload[0]&0x0f)*4:] // strip IP header on raw sockets
		}
		// Echo reply (type 0) with our id? (DGRAM sockets rewrite the id,
		// so match on the seq+payload there.)
		if len(payload) >= 16 && payload[0] == 0 &&
			binary.BigEndian.Uint16(payload[6:]) == uint16(seq) &&
			string(payload[8:16]) == "netdiag0" {
			return time.Since(start), nil
		}
	}
	return 0, errors.New("timeout")
}

func icmpSocket() (fd int, raw bool, err error) {
	if fd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMP); err == nil {
		return fd, false, nil
	}
	if fd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP); err == nil {
		return fd, true, nil
	}
	return 0, false, err
}

func icmpChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + sum>>16
	}
	return ^uint16(sum)
}
