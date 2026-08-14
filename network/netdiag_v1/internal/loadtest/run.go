package loadtest

// The measurement half: fill the link, and ping through the congestion while
// it is full. Everything here is consented and bounded — this is the one tier
// of netdiag that deliberately consumes bandwidth, so it never runs as part
// of a plain scan and it states its data cost before starting.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// minLoadBytes is the floor below which we refuse to call the link "loaded".
// 2 MB inside the load window is slower than any link worth grading, so
// anything under it means the transfer did not really happen — and a grade
// from an unloaded link is worse than no grade at all.
const minLoadBytes = 2 << 20

// Pinger is the latency probe (injected so this package does not depend on
// the collectors, and so tests can drive it with a fake).
type Pinger func(host string, timeout time.Duration) (time.Duration, error)

// Config for one run.
type Config struct {
	DownloadURL  string        // what to pull to fill the pipe
	Fallbacks    []string      // tried in order when the primary is blocked
	LatencyHost  string        // who to ping through the congestion
	IdleWindow   time.Duration // how long to measure the quiet baseline
	LoadWindow   time.Duration // how long to keep the link busy
	MaxBytes     int64         // hard ceiling on data used
	Streams      int           // parallel connections (1 stream cannot fill a fast line)
	ContractDown float64       // Mbps the customer pays for (0 = unknown)
	Ping         Pinger
}

// userAgent identifies the tool honestly. It is NOT cosmetic: Cloudflare's
// speed endpoint answers HTTP 403 to Go's default "Go-http-client/1.1"
// (field run on a healthy laptop — the feature was dead for everyone until
// this was found). Servers that serve test payloads expect a real client.
const userAgent = "netdiag/1.x (network diagnostic tool; +passive-safe)"

// fallbackURLs are the public test payloads raced against each other; the
// FASTEST is used, not the first to answer (see fastestEndpoint). Cloudflare
// sits last because it answers 403 to non-browser clients regardless of
// User-Agent — chasing browser fingerprints to get past that would be
// dishonest about what this tool is.
var fallbackURLs = []string{
	"http://speedtest.tele2.net/100MB.zip",
	"http://ipv4.download.thinkbroadband.com/100MB.zip",
	"https://proof.ovh.net/files/100Mb.dat",
	"https://speed.cloudflare.com/__down?bytes=100000000",
}

// probeBytes/probeWindow bound the server-selection sprint. Field run: OVH
// answered first and delivered 6 Mbps while tele2 delivered 175 Mbps on the
// same link in the same minute — so "the first server that answers" is a
// broken way to choose. Racing them briefly costs a few MB and turns the
// throughput number from a property of the server into a property of the LINE.
const (
	probeBytes  = 6 << 20
	probeWindow = 1500 * time.Millisecond
)

// fastestEndpoint races the reachable candidates and returns the quickest,
// with a note for the report. A single slow server otherwise silently caps
// the entire measurement.
func (c Config) fastestEndpoint(ctx context.Context, candidates []string) (string, []string, []string) {
	type result struct {
		url  string
		mbps float64
		err  error
	}
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results []result
	)
	for _, u := range candidates {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(ctx, probeWindow)
			defer cancel()
			probe := c
			probe.DownloadURL = url
			start := time.Now()
			n, _, err := probe.downloadOne(pctx, probeBytes)
			mu.Lock()
			results = append(results, result{url, Mbps(n, time.Since(start)), err})
			mu.Unlock()
		}(u)
	}
	wg.Wait()

	best, bestMbps := "", 0.0
	var notes, failures []string
	for _, r := range results {
		if r.mbps <= 0 {
			reason := "no data"
			if r.err != nil {
				reason = r.err.Error()
			}
			failures = append(failures, fmt.Sprintf("      %s → %s", r.url, reason))
			continue
		}
		notes = append(notes, fmt.Sprintf("%s ≈%.0f Mbps", shortHost(r.url), r.mbps))
		if r.mbps > bestMbps {
			best, bestMbps = r.url, r.mbps
		}
	}
	return best, notes, failures
}

func shortHost(rawURL string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(rawURL, "https://"), "http://")
	if i := strings.Index(s, "/"); i > 0 {
		s = s[:i]
	}
	return s
}

// DefaultConfig: ~15 s of work and a firm data ceiling. The endpoints are
// public speed-test origins that exist to serve exactly this.
func DefaultConfig(ping Pinger) Config {
	return Config{
		DownloadURL: fallbackURLs[0],
		Fallbacks:   fallbackURLs[1:],
		LatencyHost: "1.1.1.1",
		IdleWindow:  4 * time.Second,
		LoadWindow:  10 * time.Second,
		MaxBytes:    100 << 20, // 100 MB ceiling
		Streams:     4,         // see downloadParallel: one stream under-reads fast links
		Ping:        ping,
	}
}

// EstimatedCost is what the user is told BEFORE anything runs. Consent needs
// a number, not a vague "this uses some data".
func (c Config) EstimatedCost() string {
	extra := ""
	if len(c.Fallbacks) > 0 {
		extra = fmt.Sprintf(" It first spends %s racing %d public servers (a few MB each) "+
			"so the result measures YOUR line rather than a slow test host.",
			probeWindow, len(c.Fallbacks)+1)
	}
	return fmt.Sprintf("This test downloads up to %d MB (it stops at %s or at the size limit, "+
		"whichever comes first) and pings %s while doing it.%s",
		c.MaxBytes>>20, c.LoadWindow, c.LatencyHost, extra)
}

// Run measures idle latency, then saturates the link and measures latency
// again during the transfer. Cancelling ctx ends it early and still returns
// whatever was measured — a truncated result is marked, never discarded.
func (c Config) Run(ctx context.Context) (Result, error) {
	res := Result{Target: c.LatencyHost, ContractDown: c.ContractDown}

	// --- 0. can we even reach the endpoint? ---
	// Checked FIRST so the failure names its own cause instead of arriving
	// as a mysterious "moved almost nothing" after the measurement windows.
	candidates := append([]string{c.DownloadURL}, c.Fallbacks...)
	var reachErrs []string
	picked := ""
	if len(candidates) == 1 {
		// An explicit -url: use it or fail, no racing and no substitution.
		if err := c.reachableURL(ctx, candidates[0]); err != nil {
			reachErrs = append(reachErrs, fmt.Sprintf("      %s → %v", candidates[0], err))
		} else {
			picked = candidates[0]
		}
	} else {
		var speeds []string
		picked, speeds, reachErrs = c.fastestEndpoint(ctx, candidates)
		if len(speeds) > 1 {
			res.EndpointNotes = append(res.EndpointNotes,
				"picked the fastest of "+strings.Join(speeds, ", "))
		}
	}
	if picked == "" {
		return res, fmt.Errorf("no usable test endpoint (tried %d):\n%s\n\n"+
			"    The bufferbloat test needs to download from a public server. If normal\n"+
			"    browsing works, these may be blocked on this network — pass your own\n"+
			"    with -url pointing at any large file.",
			len(candidates), strings.Join(reachErrs, "\n"))
	}
	c.DownloadURL = picked
	res.Endpoint = picked
	if len(reachErrs) > 0 {
		res.EndpointNotes = append(res.EndpointNotes,
			fmt.Sprintf("%d endpoint(s) unusable: %s",
				len(reachErrs), strings.TrimSpace(strings.Join(reachErrs, "; "))))
	}

	// --- 1. the quiet baseline ---
	idle := c.sampleLatency(ctx, c.IdleWindow, 250*time.Millisecond)
	if len(idle) == 0 {
		return res, fmt.Errorf("no latency samples on an idle link — cannot judge bufferbloat "+
			"(is ICMP to %s blocked?)", c.LatencyHost)
	}
	res.IdleRTTms = Median(idle)

	// --- 2. fill the link, sampling latency THROUGH the congestion ---
	loadCtx, stopLoad := context.WithTimeout(ctx, c.LoadWindow)
	defer stopLoad()

	var (
		wg       sync.WaitGroup
		gotBytes int64
		elapsed  time.Duration
		dlErr    error
		loaded   []float64
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		gotBytes, elapsed, dlErr = c.downloadParallel(loadCtx)
		// Fail fast: if the transfer died immediately (no route, blocked
		// endpoint, captive portal), there is nothing to measure and no
		// reason to make the user watch a ten-second countdown first.
		if gotBytes < minLoadBytes {
			stopLoad()
		}
	}()

	// Give the transfer a moment to actually fill the buffers before judging
	// them: sampling from t=0 would average in the pre-congestion latency and
	// flatter a bad link.
	select {
	case <-time.After(1500 * time.Millisecond):
	case <-loadCtx.Done():
	}
	loaded = c.sampleLatency(loadCtx, c.LoadWindow-1500*time.Millisecond, 200*time.Millisecond)
	wg.Wait()

	// A bufferbloat grade is only meaningful if the link was ACTUALLY loaded.
	// Field run: the download silently moved 0 bytes (no internet path from
	// that VM) and the tool still printed "grade A — calls will not suffer",
	// which is a confident lie. Anything below a real transfer is unmeasured.
	if gotBytes < minLoadBytes {
		reason := "the transfer moved almost nothing"
		if dlErr != nil {
			reason = fmt.Sprintf("the transfer failed (%v)", dlErr)
		}
		return res, fmt.Errorf("%s — only %d KB in %s, so the link was never "+
			"actually loaded and NO bufferbloat grade can be given. Check that this "+
			"machine can reach %s, or pass -url with a reachable large file",
			reason, gotBytes/1024, elapsed.Round(time.Millisecond), c.DownloadURL)
	}
	if len(loaded) == 0 {
		res.Truncated = true
		return res, fmt.Errorf("the link filled but no latency samples came back under load")
	}

	res.LoadedRTTms = Median(loaded)
	res.DeltaMs = res.LoadedRTTms - res.IdleRTTms
	if res.DeltaMs < 0 {
		res.DeltaMs = 0 // load cannot make a link faster; treat as no bloat
	}
	res.Grade = GradeFor(res.DeltaMs)
	res.Samples = len(loaded)
	res.DownMbps = Mbps(gotBytes, elapsed)
	res.Streams = c.Streams
	if ctx.Err() != nil {
		res.Truncated = true
	}
	return res, nil
}

// sampleLatency pings on an interval until the window closes.
func (c Config) sampleLatency(ctx context.Context, window, every time.Duration) []float64 {
	var out []float64
	if window <= 0 {
		return out
	}
	deadline := time.After(window)
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return out
		case <-deadline:
			return out
		case <-tick.C:
			if rtt, err := c.Ping(c.LatencyHost, 900*time.Millisecond); err == nil {
				out = append(out, float64(rtt.Microseconds())/1000)
			}
			// A failed probe is not a zero: silence is recorded by absence,
			// and Median over fewer samples is flagged in Honest().
		}
	}
}

// downloadParallel runs several connections at once. A SINGLE HTTP stream to
// a distant server is limited by TCP window / per-connection shaping and
// typically reads a fraction of a fast line — the field run measured 2 Mbps
// on a 500 Mbps connection and the tool then blamed the ISP for it. Real
// speed tests use parallel streams for exactly this reason.
func (c Config) downloadParallel(ctx context.Context) (int64, time.Duration, error) {
	streams := c.Streams
	if streams < 1 {
		streams = 1
	}
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		total int64
		first error
	)
	start := time.Now()
	perStream := c.MaxBytes / int64(streams)
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, _, err := c.downloadOne(ctx, perStream)
			mu.Lock()
			total += n
			if err != nil && first == nil {
				first = err
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	return total, time.Since(start), first
}

// downloadOne pulls from the endpoint until the context expires or its share
// of the byte ceiling is hit, and reports how much moved in how long.
func (c Config) downloadOne(ctx context.Context, maxBytes int64) (int64, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.DownloadURL, nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("User-Agent", userAgent)
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, time.Since(start), err
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, maxBytes))
	elapsed := time.Since(start)
	// A cancelled context is the normal ending ONLY when the transfer had
	// already done its job. Blanking the error unconditionally hid the real
	// cause from the user (field run: "moved almost nothing" with no reason,
	// which is unactionable) — so silence the error only on a full run.
	if ctx.Err() != nil && n >= minLoadBytes/int64(max(c.Streams, 1)) {
		err = nil
	}
	return n, elapsed, err
}

// reachable does a cheap pre-flight so a broken endpoint is reported as
// exactly that, with the underlying error, before the user waits through a
// load window that cannot work.
func (c Config) reachableURL(ctx context.Context, url string) error {
	pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(pctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("the endpoint answered HTTP %d", resp.StatusCode)
	}
	if _, err := io.CopyN(io.Discard, resp.Body, 1024); err != nil && err != io.EOF {
		return fmt.Errorf("the endpoint accepted the connection but sent nothing: %w", err)
	}
	return nil
}
