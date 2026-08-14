//go:build linux

package collectors

import (
	"context"
	"net"
	"netdiag/internal/schema"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// -------------------------- DNS hidden causes (L7, §4.1 v2.3 additions a/b/c)

// dnsExtraCollector covers the three classic hidden DNS causes:
//
//	(a) hosts-file overrides — stale /etc/hosts entries pinning names,
//	(b) browser-DoH bypass — Firefox TRR resolving past the OS resolver
//	    (config-read heuristic; "unknown" when no profile is readable),
//	(c) resolver disagreement — each configured resolver queried directly
//	    and answers diffed, plus a hijack check (public probe name
//	    resolving to a private IP = captive portal or DNS hijack).
type dnsExtraCollector struct{}

func (dnsExtraCollector) Name() string      { return "dns_extra" }
func (dnsExtraCollector) Privilege() string { return schema.PrivUnprivileged }

func (dnsExtraCollector) Timeout() time.Duration { return 10 * time.Second }

func (dnsExtraCollector) Collect(ctx context.Context) (map[string]any, error) {
	data := map[string]any{}

	// (a) hosts-file overrides.
	overrides := hostsOverrides("/etc/hosts")
	data["hosts_override_count"] = len(overrides)
	if len(overrides) > 0 {
		data["hosts_overrides"] = overrides
	}

	// (b) browser DoH: Firefox TRR + Chrome/Chromium managed policy
	// (config heuristics, honestly tri-state) plus on-the-wire evidence —
	// established connections to known DoH/DoT endpoints right now.
	data["browser_doh"] = firefoxDoH()
	data["chrome_doh_policy"] = chromeDoHPolicy()
	doh, dot := dohConnections()
	data["doh_connections_active"] = len(doh) > 0
	data["dot_connections_active"] = len(dot) > 0
	if len(doh) > 0 {
		data["doh_connection_targets"] = doh
	}
	if len(dot) > 0 {
		data["dot_connection_targets"] = dot
	}

	// (c) per-resolver direct queries + disagreement + hijack check.
	servers := resolvConfServers("/etc/resolv.conf")
	answers := map[string][]string{}
	var hijack bool
	for _, s := range servers {
		ips, err := queryVia(ctx, s, dnsProbeName)
		if err != nil {
			answers[s] = []string{"error: " + err.Error()}
			continue
		}
		sort.Strings(ips)
		answers[s] = ips
		for _, ip := range ips {
			if p := net.ParseIP(ip); p != nil && p.IsPrivate() {
				hijack = true // a known public name answered with a LAN address
			}
		}
	}
	data["dns_public_name_private_ip"] = hijack
	if len(answers) > 0 {
		data["resolver_answers"] = answers
	}
	if len(servers) > 1 {
		data["resolvers_disagree"] = disagree(answers)
	}

	// DNSSEC validation state: does the resolver in use set the AD flag
	// for a known-signed zone?
	if len(servers) > 0 {
		data["dnssec_probe_name"] = dnssecProbeName
		if validating, err := dnssecValidating(ctx, servers[0], dnssecProbeName); err == nil {
			data["dnssec_validating"] = validating
		}
	}
	return data, nil
}

// firefoxDoH: Linux profile locations.
func firefoxDoH() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "unknown"
	}
	return firefoxDoHFromGlobs(
		filepath.Join(home, ".mozilla/firefox/*/prefs.js"),
		filepath.Join(home, "snap/firefox/common/.mozilla/firefox/*/prefs.js"),
	)
}

func resolvConfServers(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return ResolvConfServers(string(b))
}
