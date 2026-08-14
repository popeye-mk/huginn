//go:build linux

package collectors

import (
	"context"
	"net"
	"os"
	"syscall"
	"time"

	"netdiag/internal/run"
	"netdiag/internal/schema"
)

// --------------------------------------------- path quality / net_quality (§4.1)

// qualityCollector measures loss %, RTT and jitter over an N-packet window to
// the gateway and to a known-good public anchor, and reads the kernel's
// path-MTU for the public route (a UDP connect performs only a route lookup —
// nothing leaves the machine for the MTU read). This is the collector that
// separates "internet is down" from "internet is bad", and the difference
// between gateway-clean/upstream-lossy is the seed of the v1.1 blame partition.
type qualityCollector struct{}

func (qualityCollector) Name() string      { return "net_quality" }
func (qualityCollector) Privilege() string { return schema.PrivUnprivileged }

// The passive sweep budget is 30 s (§16); quality gets a bigger slice than
// the default 5 s because it is the only multi-probe collector.
func (qualityCollector) Timeout() time.Duration { return 15 * time.Second }

func (qualityCollector) Collect(ctx context.Context) (map[string]any, error) {
	gwB, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil, err
	}
	gw := defaultGatewayFrom(string(gwB))
	if gw == "" {
		return nil, run.SkipError{ReasonText: "no default route — no path to measure"}
	}

	data := map[string]any{"upstream_probe_target": upstreamAddr}

	gwStats, gwErr := probeWindow(ctx, gw)
	if gwErr != nil {
		if isPermissionErr(gwErr) {
			return nil, run.SkipError{ReasonText: "ICMP not permitted at this privilege"}
		}
		return nil, gwErr
	}
	gwStats.fill(data, "gateway_q")

	upStats, upErr := probeWindow(ctx, upstreamAddr)
	if upErr == nil {
		upStats.fill(data, "upstream")
		data["upstream_reachable"] = upStats.received > 0
	}

	if mtu, err := pathMTU(upstreamAddr); err == nil && mtu > 0 {
		data["path_mtu"] = mtu
	}
	return data, nil
}

func probeWindow(ctx context.Context, target string) (windowStats, error) {
	var w windowStats
	for i := 0; i < qualityProbes; i++ {
		if ctx.Err() != nil {
			break
		}
		rtt, err := icmpEcho(target, 100+i, 700*time.Millisecond)
		w.sent++
		if err == nil {
			w.received++
			w.rtts = append(w.rtts, float64(rtt.Microseconds())/1000.0)
		} else if isPermissionErr(err) {
			return w, err
		}
	}
	return w, nil
}

const ipMTUOpt = 14 // IP_MTU — not exported by syscall, stable Linux ABI value

// pathMTU: UDP connect (route lookup only, no packet) then read IP_MTU.
func pathMTU(target string) (int, error) {
	conn, err := net.Dial("udp4", target+":53")
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	uc, ok := conn.(*net.UDPConn)
	if !ok {
		return 0, nil
	}
	rc, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	mtu := 0
	var serr error
	_ = rc.Control(func(fd uintptr) {
		mtu, serr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IP, ipMTUOpt)
	})
	return mtu, serr
}
