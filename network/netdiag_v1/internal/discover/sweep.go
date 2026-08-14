package discover

// The ACTIVE tier. Everything else in netdiag touches only this machine, its
// own gateway and its own resolver. A sweep touches other people's machines,
// so it carries the authorization gate (§3): a flag AND a typed confirmation,
// a refusal to run on anything larger than a /22, and a hard cap on hosts.
//
// It is also deliberately weak as a scanner: ICMP echo plus the ARP table it
// populates. It does not port-scan, fingerprint, or probe services. Naming
// who is present is the diagnostic value; anything more is nmap's job, and
// the spec draws that line on purpose (§14).

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// MaxSweepHosts caps a run regardless of prefix length: a /22 is 1022 hosts,
// which is already more than a diagnostic needs.
const MaxSweepHosts = 1024

// SweepLimitError explains a refusal in the terms the operator needs.
type SweepLimitError struct{ Reason string }

func (e SweepLimitError) Error() string { return e.Reason }

// HostsIn returns the usable host addresses of a CIDR, refusing ranges that
// are too large to sweep responsibly.
func HostsIn(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	if ip.To4() == nil {
		return nil, SweepLimitError{"IPv6 ranges are far too large to sweep — " +
			"use the passive view, or name specific hosts with `why cant-reach`"}
	}
	ones, bits := ipnet.Mask.Size()
	if size := 1 << (bits - ones); size > MaxSweepHosts*2 {
		return nil, SweepLimitError{fmt.Sprintf(
			"%s covers %d addresses; netdiag refuses to sweep more than %d "+
				"(narrow the range, e.g. a /24)", cidr, size, MaxSweepHosts)}
	}
	var out []string
	for cur := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(cur); cur = nextIP(cur) {
		out = append(out, cur.String())
		if len(out) > MaxSweepHosts+2 {
			break
		}
	}
	// Drop network and broadcast addresses.
	if len(out) > 2 {
		out = out[1 : len(out)-1]
	}
	return out, nil
}

func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	return next
}

// Pinger matches the collectors' ICMP prober.
type Pinger func(host string, timeout time.Duration) (time.Duration, error)

// Sweep pings every host in the list with bounded concurrency and returns the
// ones that answered. Silence is NOT absence — plenty of hosts drop ICMP —
// and the caller is expected to say so in the report.
func Sweep(ctx context.Context, hosts []string, ping Pinger, concurrency int) []string {
	if concurrency <= 0 {
		concurrency = 32
	}
	var (
		mu    sync.Mutex
		alive []string
		wg    sync.WaitGroup
	)
	sem := make(chan struct{}, concurrency)
	for _, h := range hosts {
		select {
		case <-ctx.Done():
			wg.Wait()
			return alive
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()
			if _, err := ping(host, 700*time.Millisecond); err == nil {
				mu.Lock()
				alive = append(alive, host)
				mu.Unlock()
			}
		}(h)
	}
	wg.Wait()
	return alive
}

// AuthorizationText is what the operator must read before a sweep. It names
// what will happen, to whom, and asks for a deliberate confirmation — the
// spec's §3 gate, in plain words.
func AuthorizationText(cidr string, hosts int) string {
	return fmt.Sprintf(`  AUTHORIZATION REQUIRED

  Everything else netdiag does touches only this computer, its own gateway
  and its own resolver. This does something different:

    it sends a ping to %d addresses on %s

  That means contacting OTHER people's machines. On a network you do not
  administer — a client site, a hotel, an office you are visiting — doing
  that without permission may breach policy or law, however harmless a ping is.

  Only continue if you administer this network or have been asked to
  investigate it.`, hosts, cidr)
}
