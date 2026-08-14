//go:build windows

package collectors

import "time"

// ProbeICMP exposes one ICMP echo to the triage layer-walks (§6) —
// IcmpSendEcho, unprivileged on Windows.
func ProbeICMP(target string, timeout time.Duration) (time.Duration, error) {
	return icmpEchoWin(target, timeout)
}

func IsPermissionError(_ error) bool { return false }
