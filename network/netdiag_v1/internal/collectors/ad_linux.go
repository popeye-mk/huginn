//go:build linux

package collectors

import (
	"context"
	"os"
	"strings"

	"netdiag/internal/schema"
)

// --------------------------- domain / AD client state, passive (L7, §4.1 v2.3)

// adCollector — the Linux half of the AD story: is this machine joined to a
// realm (sssd/winbind/krb5), and which one. The Windows collector
// (dsregcmd / secure channel) is v1-remaining; consumed by `why cant-login`
// in v1.1.
type adCollector struct{}

func (adCollector) Name() string      { return "ad_state" }
func (adCollector) Privilege() string { return schema.PrivUnprivileged }

func (adCollector) Collect(_ context.Context) (map[string]any, error) {
	joined := false
	realm := ""
	if b, err := os.ReadFile("/etc/krb5.conf"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "default_realm") {
				if i := strings.Index(line, "="); i > 0 {
					realm = strings.TrimSpace(line[i+1:])
				}
			}
		}
	}
	if b, err := os.ReadFile("/etc/nsswitch.conf"); err == nil {
		s := string(b)
		if strings.Contains(s, "sss") || strings.Contains(s, "winbind") {
			joined = true
		}
	}
	if _, err := os.Stat("/etc/krb5.keytab"); err == nil {
		joined = true
	}
	data := map[string]any{"ad_domain_joined": joined && realm != ""}
	if realm != "" {
		data["ad_realm"] = realm
	}
	return data, nil
}
