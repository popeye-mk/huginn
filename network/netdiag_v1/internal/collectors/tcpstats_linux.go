//go:build linux

package collectors

import (
	"context"
	"os"
	"strconv"
	"strings"

	"netdiag/internal/schema"
)

// ---------------------------------- TCP pathology counters (L4, §4.1 v2.3)

// tcpStatsCollector reads the kernel's own protocol counters from
// /proc/net/snmp and /proc/net/netstat — retransmission ratio, resets,
// failed attempts since boot. Zero probes, zero privilege: the kernel
// already counted it.
type tcpStatsCollector struct{}

func (tcpStatsCollector) Name() string      { return "tcp_stats" }
func (tcpStatsCollector) Privilege() string { return schema.PrivUnprivileged }

func (tcpStatsCollector) Collect(_ context.Context) (map[string]any, error) {
	tcp, err := procTable("/proc/net/snmp", "Tcp:")
	if err != nil {
		return nil, err
	}
	data := map[string]any{}
	outSegs := tcp["OutSegs"]
	retrans := tcp["RetransSegs"]
	data["tcp_out_segs"] = outSegs
	data["tcp_retrans_segs"] = retrans
	// Ratios only above a minimum volume — tiny denominators turn noise
	// into a "storm" (Windows field-run lesson, applied on both OSes).
	if outSegs >= 1000 {
		// percent with one decimal, as a float fact for _above thresholds
		data["tcp_retrans_pct"] = float64(retrans*1000/outSegs) / 10
		data["tcp_resets_per_1k"] = tcp["OutRsts"] * 1000 / outSegs
	}
	data["tcp_resets_out"] = tcp["OutRsts"]
	data["tcp_attempt_fails"] = tcp["AttemptFails"]
	data["tcp_estab_resets"] = tcp["EstabResets"]

	if ext, err := procTable("/proc/net/netstat", "TcpExt:"); err == nil {
		data["tcp_listen_drops"] = ext["ListenDrops"]
		data["tcp_syn_retrans"] = ext["TCPSynRetrans"]
	}
	return data, nil
}

// procTable parses the header/value line pairs of /proc/net/snmp-style files.
func procTable(path, prefix string) (map[string]int64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(b), "\n")
	for i := 0; i+1 < len(lines); i++ {
		if strings.HasPrefix(lines[i], prefix) && strings.HasPrefix(lines[i+1], prefix) {
			keys := strings.Fields(lines[i])[1:]
			vals := strings.Fields(lines[i+1])[1:]
			out := map[string]int64{}
			for j := 0; j < len(keys) && j < len(vals); j++ {
				n, _ := strconv.ParseInt(vals[j], 10, 64)
				out[keys[j]] = n
			}
			return out, nil
		}
	}
	return map[string]int64{}, nil
}
