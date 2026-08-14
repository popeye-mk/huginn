// Package watch is the time-domain mode (§9): the motion camera to the rest
// of the tool's still photograph. It sits on the connection for a bounded
// window, samples a small set of passive facts on an interval, and emits
// TIMESTAMPED INTERPRETED EVENTS — not a graph to babysit.
//
// Three disciplines, all inherited from the snapshot side:
//   - Absence is never health: a sample that fails to measure something
//     records "unmeasured", never a green.
//   - A transition is only an event if it crosses a threshold that matters;
//     improvement is never an event (it is recovery, and recovery is noted
//     as the closing half of the event that preceded it).
//   - Baseline-aware (§5.2): "loss spiked to 22%" is judged against what is
//     normal AT THIS LOCATION, not in a vacuum.
//
// This package holds no I/O: samples come in, events come out. That is what
// makes the intermittent-fault logic testable without an intermittent fault.
package watch

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// Sample is one tick's worth of watched facts. Missing values are absent
// (nil), never zero — a failed measurement must not read as a good one.
type Sample struct {
	At time.Time `json:"at"`

	LinkUp        *bool    `json:"link_up,omitempty"`
	IPv4          string   `json:"ipv4,omitempty"`
	GatewayIP     string   `json:"gateway_ip,omitempty"`
	GatewayMAC    string   `json:"gateway_mac,omitempty"`
	DHCPServer    string   `json:"dhcp_server,omitempty"`
	DefaultRoutes *int     `json:"default_route_count,omitempty"`
	GatewayLoss   *float64 `json:"gateway_loss_pct,omitempty"`
	GatewayRTT    *float64 `json:"gateway_rtt_ms,omitempty"`
	DNSOK         *bool    `json:"dns_ok,omitempty"`
	DNSLatency    *float64 `json:"dns_latency_ms,omitempty"`
	WifiBSSID     string   `json:"wifi_bssid,omitempty"`
	WifiRSSI      *float64 `json:"wifi_rssi_dbm,omitempty"`
	WifiChannel   *int     `json:"wifi_channel,omitempty"`
}

// Event is one interpreted thing that happened, with the time it happened.
type Event struct {
	At       time.Time `json:"at"`
	Kind     string    `json:"kind"`     // stable id, used for periodicity grouping
	Severity string    `json:"severity"` // critical | warning | info
	What     string    `json:"what"`     // one human line, already interpreted
}

// Normal is the location baseline (§5.2) reduced to what watch judges
// against. Zero values mean "no baseline" — thresholds then fall back to
// absolute defaults, and the report says so.
type Normal struct {
	Known      bool
	LossPct    float64
	RTTms      float64
	DNSms      float64
	GatewayMAC string
	Source     string // where the baseline came from, for the header
}

// Thresholds — deliberately conservative, because a watch that cries wolf
// every tick is worse than no watch at all.
const (
	lossSpikeAbs    = 10.0 // pts of loss that is an event with no baseline
	lossSpikeOver   = 10.0 // pts ABOVE this location's normal
	rttSpikeFactor  = 3.0  // × the location's normal RTT
	rttSpikeAbsMs   = 250.0
	dnsSpikeFactor  = 3.0
	dnsSpikeAbsMs   = 1500.0
	rssiDropDB      = 12.0 // sudden drop that explains a stall
	rssiFloorDBm    = -75.0
	minSamplesForPd = 3 // recurrences needed before periodicity is claimed
)

// Watcher folds samples into events. Feed it with Add; it keeps only the
// previous sample plus the running record, so a 12-hour run costs nothing.
type Watcher struct {
	Normal  Normal
	Events  []Event
	Samples int

	prev      *Sample
	lossOpen  bool // a loss episode is currently open
	dnsOpen   bool
	linkOpen  bool
	lossPeak  float64
	rttSeen   []float64
	lossSeen  []float64
	dnsSeen   []float64
	unmeasure map[string]int
	started   time.Time
	last      time.Time
}

func New(n Normal) *Watcher {
	return &Watcher{Normal: n, unmeasure: map[string]int{}}
}

// Add folds one sample in and returns the events it produced (so a caller can
// print them live as they happen).
func (w *Watcher) Add(s Sample) []Event {
	var out []Event
	if w.Samples == 0 {
		w.started = s.At
	}
	w.Samples++
	w.last = s.At
	emit := func(kind, sev, what string) {
		e := Event{At: s.At, Kind: kind, Severity: sev, What: what}
		w.Events = append(w.Events, e)
		out = append(out, e)
	}

	// --- link: the hardest fault to catch by snapshot, the easiest here ---
	// A fault present on the FIRST sample is a standing condition, not a
	// transition: saying "the link went down" about something that was
	// already down before the watch started is a lie about when it happened.
	if s.LinkUp == nil {
		w.unmeasure["link"]++
	} else if !*s.LinkUp {
		if !w.linkOpen {
			w.linkOpen = true
			if w.Samples == 1 {
				emit("link_down_at_start", "critical",
					"the link was ALREADY down when the watch started — a standing fault, not an intermittent one")
			} else {
				emit("link_down", "critical", "the link went DOWN — nothing above L1 can work while this lasts")
			}
		}
	} else if w.linkOpen {
		w.linkOpen = false
		emit("link_up", "info", "the link came back up (a flap just completed — this is the intermittent the user reported)")
	}

	// --- identity changes: the security-relevant ones (§5.2 drift) ---
	if w.prev != nil {
		if a, b := w.prev.GatewayMAC, s.GatewayMAC; a != "" && b != "" && a != b {
			emit("gateway_mac_change", "critical",
				fmt.Sprintf("the gateway's MAC changed %s → %s — a router swap/failover, or ARP spoofing; treat as security-relevant until explained", a, b))
		}
		if a, b := w.prev.IPv4, s.IPv4; a != "" && b != "" && a != b {
			emit("address_change", "warning",
				fmt.Sprintf("this machine's address changed %s → %s (lease change or a reconnect — every open connection died at that moment)", a, b))
		}
		if a, b := w.prev.GatewayIP, s.GatewayIP; a != "" && b != "" && a != b {
			emit("gateway_change", "warning",
				fmt.Sprintf("the default gateway changed %s → %s — the path out of this network moved", a, b))
		}
		if a, b := w.prev.DHCPServer, s.DHCPServer; a != "" && b != "" && a != b {
			emit("dhcp_server_change", "critical",
				fmt.Sprintf("the DHCP server answering changed %s → %s — a second (possibly rogue) server is handing out leases", a, b))
		}
		if a, b := w.prev.WifiBSSID, s.WifiBSSID; a != "" && b != "" && a != b {
			ch := ""
			if s.WifiChannel != nil {
				ch = fmt.Sprintf(" (now channel %d)", *s.WifiChannel)
			}
			emit("wifi_roam", "info",
				fmt.Sprintf("Wi-Fi roamed to another access point %s → %s%s — brief stalls around this moment are roaming, not the ISP", a, b, ch))
		}
		if a, b := w.prev.WifiRSSI, s.WifiRSSI; a != nil && b != nil && *a-*b >= rssiDropDB {
			emit("wifi_rssi_drop", "warning",
				fmt.Sprintf("Wi-Fi signal fell %.0f dB (%.0f → %.0f dBm) — coverage, not capacity", *a-*b, *a, *b))
		}
	}
	if s.WifiRSSI != nil && *s.WifiRSSI <= rssiFloorDBm {
		w.noteFloor("wifi_weak", "warning",
			fmt.Sprintf("Wi-Fi signal is at %.0f dBm — below the usable floor; expect retries and stalls", *s.WifiRSSI), s.At, &out)
	}

	// --- loss episodes: open on the spike, close on recovery with duration ---
	if s.GatewayLoss == nil {
		w.unmeasure["gateway_loss"]++
	} else {
		w.lossSeen = append(w.lossSeen, *s.GatewayLoss)
		if w.lossIsSpike(*s.GatewayLoss) {
			if !w.lossOpen {
				w.lossOpen = true
				w.lossPeak = *s.GatewayLoss
				emit("loss_spike", "critical", fmt.Sprintf(
					"loss to the gateway spiked to %.0f%%%s", *s.GatewayLoss, w.vsNormalLoss()))
			} else if *s.GatewayLoss > w.lossPeak {
				w.lossPeak = *s.GatewayLoss
			}
		} else if w.lossOpen {
			w.lossOpen = false
			emit("loss_recovered", "info", fmt.Sprintf(
				"loss to the gateway recovered (peak was %.0f%%)", w.lossPeak))
		}
	}

	// --- latency: judged against this location's normal, not a constant ---
	if s.GatewayRTT != nil {
		w.rttSeen = append(w.rttSeen, *s.GatewayRTT)
		if w.rttIsSpike(*s.GatewayRTT) {
			w.noteFloor("rtt_spike", "warning", fmt.Sprintf(
				"gateway latency rose to %.0f ms%s — calls and remote sessions stutter at this level",
				*s.GatewayRTT, w.vsNormalRTT()), s.At, &out)
		}
	}

	// --- DNS: the layer that fails alone while everything else looks fine ---
	if s.DNSOK == nil {
		w.unmeasure["dns"]++
	} else if !*s.DNSOK {
		if !w.dnsOpen {
			w.dnsOpen = true
			switch {
			case s.LinkUp != nil && !*s.LinkUp:
				// Don't blame the resolver for a dead cable: with the link
				// down, DNS failing is a consequence, not a finding.
				emit("dns_failed_link_down", "info",
					"name resolution failed, but the link was down at the time — a consequence, not a DNS fault")
			case w.Samples == 1:
				emit("dns_failed_at_start", "critical",
					"name resolution was ALREADY failing when the watch started — a standing fault, not an intermittent one")
			default:
				emit("dns_failed", "critical",
					"name resolution FAILED while the link stayed up — 'the internet is down' with a healthy cable")
			}
		}
	} else if w.dnsOpen {
		w.dnsOpen = false
		emit("dns_recovered", "info", "name resolution recovered")
	}
	if s.DNSLatency != nil {
		w.dnsSeen = append(w.dnsSeen, *s.DNSLatency)
		if w.dnsIsSpike(*s.DNSLatency) {
			w.noteFloor("dns_slow", "warning", fmt.Sprintf(
				"DNS answered in %.0f ms — every new connection pays this before anything loads", *s.DNSLatency), s.At, &out)
		}
	}

	cp := s
	w.prev = &cp
	return out
}

// noteFloor emits at most one event per kind per 60 s, so a sustained
// condition is reported as a condition, not as one event per tick.
func (w *Watcher) noteFloor(kind, sev, what string, at time.Time, out *[]Event) {
	for i := len(w.Events) - 1; i >= 0; i-- {
		if w.Events[i].Kind == kind {
			if at.Sub(w.Events[i].At) < 60*time.Second {
				return
			}
			break
		}
	}
	e := Event{At: at, Kind: kind, Severity: sev, What: what}
	w.Events = append(w.Events, e)
	*out = append(*out, e)
}

func (w *Watcher) lossIsSpike(v float64) bool {
	if w.Normal.Known {
		return v >= w.Normal.LossPct+lossSpikeOver
	}
	return v >= lossSpikeAbs
}

func (w *Watcher) rttIsSpike(v float64) bool {
	if w.Normal.Known && w.Normal.RTTms > 0 {
		return v >= w.Normal.RTTms*rttSpikeFactor && v >= 20
	}
	return v >= rttSpikeAbsMs
}

func (w *Watcher) dnsIsSpike(v float64) bool {
	if w.Normal.Known && w.Normal.DNSms > 0 {
		return v >= w.Normal.DNSms*dnsSpikeFactor && v >= 200
	}
	return v >= dnsSpikeAbsMs
}

func (w *Watcher) vsNormalLoss() string {
	if !w.Normal.Known {
		return ""
	}
	return fmt.Sprintf(" (normal here: %.0f%%)", w.Normal.LossPct)
}

func (w *Watcher) vsNormalRTT() string {
	if !w.Normal.Known || w.Normal.RTTms <= 0 {
		return ""
	}
	return fmt.Sprintf(" (normal here: %.0f ms)", w.Normal.RTTms)
}

// Periodicity is the finding a single sample can never produce: this recurs
// on a rhythm, and the rhythm points at the cause.
type Periodicity struct {
	Kind     string
	Count    int
	MeanGap  time.Duration
	Regular  bool // gaps are tight enough to call it periodic
	Examples []time.Time
}

// Periodic groups repeated events by kind and reports their rhythm. Regular
// means the gaps' coefficient of variation is under 25% — loose enough for
// real-world jitter, tight enough that "every ~30 min" means something.
func (w *Watcher) Periodic() []Periodicity {
	byKind := map[string][]time.Time{}
	for _, e := range w.Events {
		if strings.HasSuffix(e.Kind, "_recovered") || e.Kind == "link_up" {
			continue // recoveries are the closing half, not separate occurrences
		}
		byKind[e.Kind] = append(byKind[e.Kind], e.At)
	}
	var out []Periodicity
	for kind, times := range byKind {
		if len(times) < minSamplesForPd {
			continue
		}
		sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
		var gaps []float64
		for i := 1; i < len(times); i++ {
			gaps = append(gaps, times[i].Sub(times[i-1]).Seconds())
		}
		mean, cv := meanCV(gaps)
		out = append(out, Periodicity{
			Kind: kind, Count: len(times),
			MeanGap:  time.Duration(mean * float64(time.Second)),
			Regular:  cv < 0.25,
			Examples: times,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

func meanCV(xs []float64) (mean, cv float64) {
	if len(xs) == 0 {
		return 0, 0
	}
	for _, x := range xs {
		mean += x
	}
	mean /= float64(len(xs))
	if mean == 0 {
		return 0, 0
	}
	var sd float64
	for _, x := range xs {
		sd += (x - mean) * (x - mean)
	}
	sd = math.Sqrt(sd / float64(len(xs)))
	return mean, sd / mean
}
