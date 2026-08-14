// OS-independent probe logic shared by the Linux and Windows collectors:
// SNTP, per-resolver DNS queries, DNSSEC AD-flag check, hosts-file parsing,
// PAC validation, browser-DoH config scans, and the captive-portal probe.
// Everything here is pure stdlib networking — no /proc, no DLLs.
package collectors

import (
	"context"
	"encoding/binary"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"netdiag/internal/run"
	"netdiag/internal/schema"
)

const dnsProbeName = "one.one.one.one" // stable, answered by 1.1.1.1

// cloudflare.com has been DNSSEC-signed since 2015 — a stable signed anchor.
const dnssecProbeName = "cloudflare.com"

// ------------------------------------------------------------------ SNTP

const ntpEpochOffset = 2208988800 // seconds between 1900 (NTP) and 1970 (Unix)

// sntpOffset performs one RFC 4330 client exchange and returns the clock
// offset ((t2-t1)+(t3-t4))/2.
func sntpOffset(ctx context.Context, server string) (time.Duration, string, error) {
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(server, "123"))
	if err != nil {
		return 0, server, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	req := make([]byte, 48)
	req[0] = 0x23 // LI=0 VN=4 Mode=3 (client)
	t1 := time.Now()
	putNTPTime(req[40:], t1)
	if _, err := conn.Write(req); err != nil {
		return 0, server, err
	}
	resp := make([]byte, 48)
	if _, err := conn.Read(resp); err != nil {
		return 0, server, err
	}
	t4 := time.Now()
	t2 := ntpTime(resp[32:]) // server receive
	t3 := ntpTime(resp[40:]) // server transmit
	offset := (t2.Sub(t1) + t3.Sub(t4)) / 2
	return offset, conn.RemoteAddr().String(), nil
}

func putNTPTime(b []byte, t time.Time) {
	secs := uint64(t.Unix()) + ntpEpochOffset
	frac := uint64(t.Nanosecond()) << 32 / 1e9
	binary.BigEndian.PutUint32(b, uint32(secs))
	binary.BigEndian.PutUint32(b[4:], uint32(frac))
}

func ntpTime(b []byte) time.Time {
	secs := int64(binary.BigEndian.Uint32(b)) - ntpEpochOffset
	frac := int64(binary.BigEndian.Uint32(b[4:])) * 1e9 >> 32
	return time.Unix(secs, frac)
}

// SNTPOffset exposes the SNTP exchange to the triage walks — `why
// cant-login` measures the clock against the DC itself (§6.4), since DCs
// serve NTP and Kerberos only cares about THAT offset.
func SNTPOffset(ctx context.Context, server string) (time.Duration, string, error) {
	return sntpOffset(ctx, server)
}

// PublicResolvers: the well-known public DNS services. A domain-joined
// client pointed at one of these can never find its DC — the single most
// common cant-login cause (§6.4).
var PublicResolvers = map[string]bool{
	"8.8.8.8": true, "8.8.4.4": true,
	"1.1.1.1": true, "1.0.0.1": true,
	"9.9.9.9": true, "149.112.112.112": true,
	"208.67.222.222": true, "208.67.220.220": true, // OpenDNS
	"94.140.14.14": true, "94.140.15.15": true,
}

// ------------------------------------------------------ per-resolver DNS

// queryVia resolves name against one specific server (§4.1: "tested by
// querying each resolver directly and diffing").
func queryVia(ctx context.Context, server, name string) ([]string, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 1500 * time.Millisecond}
			return d.DialContext(ctx, network, net.JoinHostPort(server, "53"))
		},
	}
	qctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return r.LookupHost(qctx, name)
}

func disagree(answers map[string][]string) bool {
	var prev []string
	first := true
	for _, ips := range answers {
		if len(ips) > 0 && strings.HasPrefix(ips[0], "error:") {
			continue // an erroring resolver is a different finding, not disagreement
		}
		if first {
			prev, first = ips, false
			continue
		}
		if strings.Join(prev, ",") != strings.Join(ips, ",") {
			return true
		}
	}
	return false
}

// dnssecValidating asks the resolver for a known-signed name with the DO
// bit set and reads the AD flag off the raw response — the stdlib resolver
// hides header flags, so the packet is hand-built.
func dnssecValidating(ctx context.Context, server, name string) (bool, error) {
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
	if err != nil {
		return false, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	q := make([]byte, 0, 64)
	q = append(q, 0x13, 0x37)             // id
	q = append(q, 0x01, 0x20)             // RD + AD ("I understand AD")
	q = append(q, 0, 1, 0, 0, 0, 0, 0, 1) // 1 question, 1 additional (OPT)
	for _, label := range strings.Split(name, ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0, 0, 1, 0, 1)                          // root, A, IN
	q = append(q, 0, 0, 41, 0x10, 0, 0, 0x80, 0, 0, 0, 0) // EDNS0 OPT, DO bit
	if _, err := conn.Write(q); err != nil {
		return false, err
	}
	resp := make([]byte, 1500)
	n, err := conn.Read(resp)
	if err != nil || n < 4 {
		return false, err
	}
	if binary.BigEndian.Uint16(resp[:2]) != 0x1337 {
		return false, nil
	}
	return resp[3]&0x20 != 0, nil // AD flag
}

// ----------------------------------------------------------- hosts file

// hostsOverrides returns non-localhost, non-comment hosts-file entries.
func hostsOverrides(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		ip := net.ParseIP(f[0])
		if ip == nil || ip.IsLoopback() {
			continue
		}
		names := f[1:]
		// Bug #24 (found by writing this test, 0.9.18): filtering the IPv6
		// boilerplate by ADDRESS CLASS missed `fe00::0 ip6-localnet`, which is
		// neither loopback nor multicast and ships in /etc/hosts on every
		// mainstream Linux. Every Linux machine therefore reported a "manual
		// hosts override" it did not have — and a finding that fires everywhere
		// is a finding people learn to scroll past, including on the machine
		// where it is real.
		//
		// Judged by NAME now: these names are the distro boilerplate, and a
		// name is what makes the line boilerplate rather than its address.
		if allBoilerplateNames(names) {
			continue
		}
		if len(out) < 20 {
			out = append(out, line)
		}
	}
	return out
}

// ---------------------------------------------------------- browser DoH

// dohProviderIPs: well-known public DoH/DoT resolver addresses. An
// ESTABLISHED connection to one of these on 443/853 is on-the-wire
// evidence something on this machine resolves outside the OS resolver.
var dohProviderIPs = map[string]bool{
	"1.1.1.1": true, "1.0.0.1": true,
	"8.8.8.8": true, "8.8.4.4": true,
	"9.9.9.9": true, "149.112.112.112": true,
	"94.140.14.14": true, "94.140.15.15": true, // AdGuard
	"185.228.168.9": true, // CleanBrowsing
	"146.112.41.2":  true, // Umbrella
}

// ip6Boilerplate is what every mainstream distro writes into /etc/hosts.
// Anything else with a real address is somebody's deliberate decision.
var ip6Boilerplate = map[string]bool{
	"localhost": true, "ip6-localhost": true, "ip6-loopback": true,
	"ip6-localnet": true, "ip6-mcastprefix": true,
	"ip6-allnodes": true, "ip6-allrouters": true, "ip6-allhosts": true,
}

func allBoilerplateNames(names []string) bool {
	for _, n := range names {
		if !ip6Boilerplate[n] && !strings.HasSuffix(n, ".localdomain") {
			return false
		}
	}
	return len(names) > 0
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// firefoxDoHFromGlobs reads network.trr.mode from any readable prefs.js
// matching the given globs. Mode 2/3 = DoH on. Tri-state string.
func firefoxDoHFromGlobs(globs ...string) string {
	any := false
	for _, g := range globs {
		matches, _ := filepath.Glob(g)
		for _, m := range matches {
			b, err := os.ReadFile(m)
			if err != nil {
				continue
			}
			any = true
			s := string(b)
			if strings.Contains(s, `"network.trr.mode", 2`) || strings.Contains(s, `"network.trr.mode", 3`) {
				return "enabled"
			}
		}
	}
	if any {
		return "disabled"
	}
	return "unknown"
}

// --------------------------------------------------------- proxy helpers

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

func proxyHostPort(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		if !strings.Contains(raw, "://") && strings.Contains(raw, ":") {
			return raw // Windows registry style "host:port"
		}
		return ""
	}
	if u.Port() == "" {
		return u.Host + ":3128"
	}
	return u.Host
}

// fetchPAC pulls the PAC and checks it is actually a PAC (FindProxyForURL),
// not a captive portal's HTML or an error page.
func fetchPAC(ctx context.Context, pacURL string) (fetched, valid bool) {
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pacURL, nil)
	if err != nil {
		return false, false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if resp.StatusCode != http.StatusOK {
		return true, false
	}
	return true, strings.Contains(string(body), "FindProxyForURL")
}

// ------------------------------------------- captive portal (both OSes)

// captiveCollector: the known-good HTTP 204 probe. A 204 means the path to
// the internet is clean; a redirect or a 200-with-body means something is
// intercepting — a captive portal, a NAC gate, or a middlebox.
type captiveCollector struct{}

func (captiveCollector) Name() string      { return "captive_portal" }
func (captiveCollector) Privilege() string { return schema.PrivUnprivileged }

const captiveProbeURL = "http://connectivitycheck.gstatic.com/generate_204"

func (captiveCollector) Collect(ctx context.Context) (map[string]any, error) {
	client := &http.Client{
		Timeout: 4 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // a redirect IS the finding
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, captiveProbeURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, run.SkipError{ReasonText: "probe did not complete: " + err.Error()}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	captive := resp.StatusCode != http.StatusNoContent
	data := map[string]any{
		"captive_probe_url":       captiveProbeURL,
		"captive_probe_status":    resp.StatusCode,
		"captive_portal_detected": captive,
	}
	if loc := resp.Header.Get("Location"); captive && loc != "" {
		data["captive_redirect_to"] = loc
	}
	return data, nil
}

// ------------------------------------------------ quality probe windows

const (
	qualityProbes = 6
	upstreamAddr  = "1.1.1.1" // stable public anchor (§4.1: "known-good public target")
)

type windowStats struct {
	sent, received int
	rtts           []float64 // ms
}

// fill writes loss/rtt/jitter facts under a prefix. Jitter is the mean of
// absolute successive RTT differences (RFC 3550 style, simplified).
func (w windowStats) fill(data map[string]any, prefix string) {
	if w.sent == 0 {
		return
	}
	data[prefix+"_loss_pct"] = (w.sent - w.received) * 100 / w.sent
	if len(w.rtts) > 0 {
		var sum float64
		for _, r := range w.rtts {
			sum += r
		}
		data[prefix+"_rtt_avg_ms"] = math.Round(sum/float64(len(w.rtts))*100) / 100
	}
	if len(w.rtts) > 1 {
		var jsum float64
		for i := 1; i < len(w.rtts); i++ {
			jsum += math.Abs(w.rtts[i] - w.rtts[i-1])
		}
		data[prefix+"_jitter_ms"] = math.Round(jsum/float64(len(w.rtts)-1)*100) / 100
	}
}
