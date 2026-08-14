// Target-specific probes for the `why cant-reach` family (§6, §6.1, §6.4).
// These are self-scoped connects to the one target the user named — still
// no scanning, no authorization gate.
package triage

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"netdiag/internal/collectors"
)

// probeTarget adds target_* facts for one host and one representative
// service port set. Port state classification: open / refused / filtered
// (timeout) — the trio every firewall conversation needs.
func probeTarget(facts map[string]any, target string, ports []int) {
	facts["target_name"] = target

	// L7: does it resolve? (IP literals pass straight through.)
	var ips []string
	if ip := net.ParseIP(target); ip != nil {
		ips = []string{target}
		facts["target_resolved"] = true
		facts["target_is_ip_literal"] = true
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		addrs, err := net.DefaultResolver.LookupHost(ctx, target)
		facts["target_resolved"] = err == nil && len(addrs) > 0
		if err != nil {
			facts["target_resolve_error"] = err.Error()
			return // nothing below can run without an address
		}
		sort.Strings(addrs)
		ips = addrs
	}
	facts["target_ips"] = ips
	ip := ips[0]

	// L3: does the host answer ICMP? (Blocked ping is common — confidence
	// stays "likely" downstream, never certain death from silence.)
	if _, err := collectors.ProbeICMP(ip, 1200*time.Millisecond); err == nil {
		facts["target_ping_ok"] = true
	} else if !collectors.IsPermissionError(err) {
		facts["target_ping_ok"] = false
	} // permission → fact stays absent: honestly unmeasured

	// L4: the service port(s).
	states := map[string]string{}
	best := ""
	for _, p := range ports {
		st := tcpState(ip, p, 2*time.Second)
		states[fmt.Sprintf("%d", p)] = st
		if st == "open" && best != "open" {
			best = "open"
			facts["target_open_port"] = p
		}
		if best == "" || (best == "filtered" && st == "refused") {
			best = st
		}
	}
	facts["target_port_states"] = states
	facts["target_port_state"] = best // open beats refused beats filtered
}

func tcpState(ip string, port int, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)), timeout)
	if err == nil {
		conn.Close()
		return "open"
	}
	if strings.Contains(err.Error(), "refused") {
		return "refused"
	}
	return "filtered"
}

// probeADSRV: DC discovery for `why cant-login` (§6.4) — do the AD SRV
// records resolve, WHICH resolver can answer them (a client pointed at
// public DNS can never find its DC), do all discovered DCs respond, and
// what does the DC's own clock say.
func probeADSRV(facts map[string]any, domain string) (dcHost string) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	// Are the configured resolvers even fit for AD? (§6.4's classic.)
	resolvers := factStrings(facts["dns_servers"])
	if len(resolvers) > 0 {
		allPublic := true
		for _, r := range resolvers {
			if !collectors.PublicResolvers[r] {
				allPublic = false
			}
		}
		facts["dns_public_resolver_only"] = allPublic
	}

	// The DC-locator record, plus Kerberos and Global Catalog SRVs.
	dcs := lookupSRV(ctx, "ldap", "dc._msdcs."+domain)
	facts["ad_srv_resolved"] = len(dcs) > 0
	if kdc := lookupSRV(ctx, "kerberos", domain); true {
		facts["ad_srv_kerberos_ok"] = len(kdc) > 0
	}
	if gc := lookupSRV(ctx, "gc", domain); true {
		facts["ad_srv_gc_ok"] = len(gc) > 0
	}
	if len(dcs) == 0 {
		// Second opinion: ask each configured resolver directly — "which
		// resolver actually answered" is the diagnostic (§4.1/§6.4).
		perResolver := map[string]bool{}
		for _, r := range resolvers {
			perResolver[r] = len(lookupSRVVia(ctx, r, "ldap", "dc._msdcs."+domain)) > 0
		}
		if len(perResolver) > 0 {
			facts["ad_srv_by_resolver"] = perResolver
			for _, ok := range perResolver {
				if ok {
					facts["ad_srv_resolved"] = true // some resolver knows the domain — the ORDER is the problem
					facts["ad_srv_resolver_mismatch"] = true
				}
			}
		}
		if facts["ad_srv_resolved"] == false {
			return ""
		}
	}
	facts["ad_dc_count"] = len(dcs)
	facts["ad_dcs"] = dcs

	// Do the DCs answer at all? Ping up to three. Prefer the IPv4 address —
	// the ICMP prober is v4-only, and resolver order is arbitrary (field-run
	// lesson: the DC's own AAAA record produced a false "0 of 1 respond").
	responding := 0
	for i, dc := range dcs {
		if i >= 3 {
			break
		}
		if ips, err := net.DefaultResolver.LookupHost(ctx, dc); err == nil && len(ips) > 0 {
			if _, err := collectors.ProbeICMP(pickIPv4(ips), 1200*time.Millisecond); err == nil {
				responding++
			}
		}
	}
	facts["ad_dcs_responding"] = responding

	// Clock offset against the DC ITSELF — DCs serve NTP (w32time), and
	// Kerberos only cares about this offset, not pool.ntp.org's.
	if len(dcs) > 0 {
		if offset, _, err := collectors.SNTPOffset(ctx, dcs[0]); err == nil {
			ms := offset.Abs().Milliseconds()
			facts["ad_dc_clock_offset_ms"] = ms
			// Outside Kerberos' ±5 min window nothing Kerberos-based can be
			// trusted as evidence — including the secure-channel verify, which
			// then fails with ACCESS_DENIED for a reason that has nothing to do
			// with the trust. Mark it unverifiable so neither the walk nor the
			// KB blames the machine account for the clock's mistake.
			if ms > 300000 {
				facts["ad_secure_channel_verifiable"] = false
			}
		}
		return dcs[0]
	}
	return ""
}

func lookupSRV(ctx context.Context, service, domain string) []string {
	qctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, srvs, err := net.DefaultResolver.LookupSRV(qctx, service, "tcp", domain)
	if err != nil {
		return nil
	}
	var out []string
	for _, s := range srvs {
		out = append(out, strings.TrimSuffix(s.Target, "."))
	}
	return out
}

// lookupSRVVia asks one specific resolver — the §6.4 "against which
// resolver" question.
func lookupSRVVia(ctx context.Context, server, service, domain string) []string {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 1500 * time.Millisecond}
			return d.DialContext(ctx, network, net.JoinHostPort(server, "53"))
		},
	}
	qctx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()
	_, srvs, err := r.LookupSRV(qctx, service, "tcp", domain)
	if err != nil {
		return nil
	}
	var out []string
	for _, s := range srvs {
		out = append(out, strings.TrimSuffix(s.Target, "."))
	}
	return out
}

// pickIPv4 returns the first IPv4 in the list, else the first address.
func pickIPv4(ips []string) string {
	for _, s := range ips {
		if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
			return s
		}
	}
	return ips[0]
}

func factStrings(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		var out []string
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
