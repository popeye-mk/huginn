//go:build linux

package collectors

import (
	"context"
	"os"
	"strings"

	"netdiag/internal/schema"
)

// -------------------------------------------------- time sync / NTP (§4.1 v2.3)

// ntpCollector: which time daemon is configured (file reads), plus one SNTP
// exchange to measure the actual clock offset. Clock drift beyond minutes
// breaks Kerberos and TLS in ways that report as "the network is down".
type ntpCollector struct{}

func (ntpCollector) Name() string      { return "time_sync" }
func (ntpCollector) Privilege() string { return schema.PrivUnprivileged }

func (ntpCollector) Collect(ctx context.Context) (map[string]any, error) {
	daemon, server := detectTimeDaemon()
	data := map[string]any{
		"time_sync_configured": daemon != "",
	}
	if daemon != "" {
		data["time_sync_daemon"] = daemon
	}
	if server == "" {
		server = "pool.ntp.org" // known-good anchor (§4.1)
	}
	offset, used, err := sntpOffset(ctx, server)
	data["ntp_query_ok"] = err == nil
	if err == nil {
		data["ntp_server_used"] = used
		data["ntp_offset_ms"] = offset.Abs().Milliseconds()
	} else {
		data["ntp_error"] = err.Error()
	}
	return data, nil
}

func detectTimeDaemon() (daemon, server string) {
	checks := []struct{ path, name, key string }{
		{"/etc/chrony/chrony.conf", "chrony", "server"},
		{"/etc/chrony.conf", "chrony", "server"},
		{"/etc/systemd/timesyncd.conf", "systemd-timesyncd", "NTP="},
		{"/etc/ntp.conf", "ntpd", "server"},
	}
	for _, c := range checks {
		b, err := os.ReadFile(c.path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, c.key) {
				f := strings.Fields(strings.TrimPrefix(line, c.key))
				if len(f) > 0 {
					return c.name, strings.TrimSpace(f[0])
				}
			}
		}
		// config file exists at all → the daemon is present even if defaults
		if c.name == "systemd-timesyncd" {
			return c.name, ""
		}
	}
	return "", ""
}
