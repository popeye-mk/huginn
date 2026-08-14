//go:build linux

package collectors

import "time"

// ProbeICMP exposes one ICMP echo to the triage layer-walks (§6) — same
// unprivileged-DGRAM-then-raw implementation the collectors use.
func ProbeICMP(target string, timeout time.Duration) (time.Duration, error) {
	return icmpEcho(target, 1, timeout)
}

// IsPermissionError reports whether a probe failed for privilege (an honest
// skip upstream) rather than because the network said no.
func IsPermissionError(err error) bool { return isPermissionErr(err) }
