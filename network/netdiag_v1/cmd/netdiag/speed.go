package main

// `netdiag speed` — the §10 tier: throughput vs what you pay for, and
// bufferbloat (latency under load).
//
// This is the ONE part of netdiag that is not free to run: it deliberately
// fills the link. So it is a separate verb, never part of a scan, it states
// its data cost and asks before starting, and it refuses to run silently in
// a script unless the caller passes -yes. Everything else about the tool's
// promise ("read-only, safe anywhere") stays true because this tier is
// opt-in and self-scoped: it moves data on the user's own link, and pings
// through the user's own uplink.

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"netdiag/internal/collectors"
	"netdiag/internal/loadtest"
	"netdiag/internal/run"
)

// speedOptions is everything the flags decide, separated from the run so the
// DECISIONS can be tested without moving a byte. This is the seam where the
// "-url was silently ignored" bug lived: the flag parsed fine, and the value
// never reached the config.
type speedOptions struct {
	cfg     loadtest.Config
	yes     bool
	jsonOut bool
}

func speedOptionsFrom(args []string) (speedOptions, error) {
	fs := flag.NewFlagSet("speed", flag.ContinueOnError)
	contract := fs.Float64("contracted", 0, "the down speed you pay for, in Mbps (enables the delivered-vs-paid verdict)")
	seconds := fs.Int("seconds", 10, "how long to keep the link busy")
	maxMB := fs.Int64("max-mb", 100, "hard ceiling on data used")
	url := fs.String("url", "", "download URL to pull from (default: a list of public speed endpoints, tried in order)")
	host := fs.String("latency-host", "", "who to ping through the congestion (default: 1.1.1.1)")
	streams := fs.Int("streams", 4, "parallel download streams (1 stream under-reads a fast line)")
	yes := fs.Bool("yes", false, "skip the consent prompt (for scripts)")
	jsonOut := fs.Bool("json", false, "emit the result as JSON")
	if err := fs.Parse(args); err != nil {
		return speedOptions{}, err
	}

	cfg := loadtest.DefaultConfig(func(h string, t time.Duration) (time.Duration, error) {
		return collectors.ProbeICMP(h, t)
	})
	cfg.LoadWindow = time.Duration(*seconds) * time.Second
	cfg.MaxBytes = *maxMB << 20
	cfg.ContractDown = *contract
	cfg.Streams = *streams
	if *url != "" {
		// An explicit -url is an instruction, not a suggestion. Leaving the
		// fallback list active silently used a different server than the one
		// asked for (field run: -url hetzner, tested against OVH).
		cfg.DownloadURL = *url
		cfg.Fallbacks = nil
	}
	if *host != "" {
		cfg.LatencyHost = *host
	}
	return speedOptions{cfg: cfg, yes: *yes, jsonOut: *jsonOut}, nil
}

func speedCmd(args []string) int {
	opts, err := speedOptionsFrom(args)
	if err != nil {
		return 2
	}
	cfg, yes, jsonOut := opts.cfg, &opts.yes, &opts.jsonOut

	fmt.Printf("netdiag %s — speed and bufferbloat\n", toolVersion)
	fmt.Println(strings.Repeat("─", 72))
	fmt.Println("\n  " + cfg.EstimatedCost())
	fmt.Println("  Unlike every other netdiag check, this one USES data and briefly")
	fmt.Println("  saturates your connection — other people on this network will feel it.")

	if !*yes {
		fmt.Print("\n  Run it? [y/N] ")
		in := bufio.NewScanner(os.Stdin)
		if !in.Scan() || !strings.HasPrefix(strings.ToLower(strings.TrimSpace(in.Text())), "y") {
			fmt.Println("  Cancelled — nothing was sent.")
			return 0
		}
	}

	// Ctrl-C ends the transfer early; whatever was measured still gets
	// reported, marked truncated.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		cancel()
	}()

	fmt.Printf("\n  measuring idle latency to %s …\n", cfg.LatencyHost)
	done := make(chan struct{})
	go func() { // a heartbeat, because a silent 15 s looks like a hang
		t := time.NewTicker(time.Second)
		defer t.Stop()
		phase := "idle"
		start := time.Now()
		for {
			select {
			case <-done:
				fmt.Fprint(os.Stderr, "\r"+strings.Repeat(" ", 60)+"\r")
				return
			case <-t.C:
				if time.Since(start) > cfg.IdleWindow {
					phase = "loading the link"
				}
				fmt.Fprintf(os.Stderr, "\r  %s … %.0fs", phase, time.Since(start).Seconds())
			}
		}
	}()

	res, err := cfg.Run(ctx)
	close(done)
	if err != nil {
		fmt.Fprintln(os.Stderr, "\n  Could not complete the test:", err)
		return 2
	}

	if *jsonOut {
		fmt.Printf("{\"idle_rtt_ms\":%.1f,\"loaded_rtt_ms\":%.1f,\"bloat_delta_ms\":%.1f,"+
			"\"grade\":%q,\"download_mbps\":%.1f,\"samples\":%d,\"truncated\":%v}\n",
			res.IdleRTTms, res.LoadedRTTms, res.DeltaMs, res.Grade, res.DownMbps,
			res.Samples, res.Truncated)
		return exitForGrade(res.Grade)
	}

	if res.Endpoint != "" {
		fmt.Printf("\n  Test server       %s\n", res.Endpoint)
	}
	// If the first choice was unusable, say so — a silent substitution makes
	// the numbers unexplainable afterwards.
	for _, n := range res.EndpointNotes {
		fmt.Printf("                    (%s)\n", n)
	}
	fmt.Printf("  Idle latency      %.1f ms\n", res.IdleRTTms)
	fmt.Printf("  Under load        %.1f ms   (+%.0f ms)\n", res.LoadedRTTms, res.DeltaMs)
	fmt.Printf("  Bufferbloat grade %s\n", res.Grade)
	if res.DownMbps > 0 {
		fmt.Printf("  Download          %.0f Mbps  (%d parallel streams)\n", res.DownMbps, res.Streams)
	}
	fmt.Printf("\n  %s\n", wrap(res.Verdict(), 70, "  "))

	// Honest limits, always — a number without its caveats is a rumour.
	overWifi := false
	snap := run.Only(collectors.ForThisOS(), []string{"wifi"}, toolVersion)
	if f := snap.Facts(); f["wifi_present"] == true && f["wifi_ssid"] != nil {
		overWifi = true
	}
	fmt.Println("\n  Honest limits of this measurement:")
	for _, h := range res.Honest(overWifi) {
		fmt.Printf("   • %s\n", h)
	}
	return exitForGrade(res.Grade)
}

// A bad grade is a non-zero exit, like a critical finding: this is a result
// someone can gate a script on.
func exitForGrade(g loadtest.Grade) int {
	if g == loadtest.GradeD || g == loadtest.GradeF {
		return 1
	}
	return 0
}

// wrap keeps the verdict readable in a narrow VM console.
func wrap(s string, width int, indent string) string {
	var out strings.Builder
	line := 0
	for _, w := range strings.Fields(s) {
		if line > 0 && line+len(w)+1 > width {
			out.WriteString("\n" + indent)
			line = 0
		} else if line > 0 {
			out.WriteString(" ")
			line++
		}
		out.WriteString(w)
		line += len(w)
	}
	return out.String()
}
