//go:build windows

package collectors

// Windows hygiene reads (§12). All of it is registry/service state this
// machine already knows about itself — no probing of anything else.

import (
	"context"
	"strings"

	"netdiag/internal/run"
	"netdiag/internal/schema"
)

type winHygieneCollector struct{}

func (winHygieneCollector) Name() string      { return "hygiene" }
func (winHygieneCollector) Privilege() string { return schema.PrivUnprivileged }

func (winHygieneCollector) Collect(ctx context.Context) (map[string]any, error) {
	listening := winListeningPorts()

	// LLMNR and NetBIOS-over-TCP/IP are the Responder attack surface: with
	// them on, any machine on the LAN can answer a mistyped name and harvest
	// credentials. Both are registry-visible and both default to ON.
	poisoning := map[string]bool{}
	// LLMNR: EnableMulticast=0 disables it; absent means enabled.
	if out, err := runTool(ctx, "reg", "query",
		`HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`, "/v", "EnableMulticast"); err == nil {
		poisoning["LLMNR"] = !strings.Contains(out, "0x0")
	} else {
		poisoning["LLMNR"] = true // no policy set = Windows default = enabled
	}
	// NetBIOS over TCP/IP: NetbiosOptions=2 disables it per interface.
	if out, err := runTool(ctx, "reg", "query",
		`HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces`, "/s", "/v", "NetbiosOptions"); err == nil {
		disabledAll := strings.Contains(out, "0x2")
		poisoning["NetBIOS-NS"] = !disabledAll
	}
	// mDNS (Windows 10+ has it on by default; EnableMDNS=0 turns it off).
	if out, err := runTool(ctx, "reg", "query",
		`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters`, "/v", "EnableMDNS"); err == nil {
		poisoning["mDNS"] = !strings.Contains(out, "0x0")
	}

	// SMBv1: the protocol behind WannaCry/EternalBlue. Judged by the optional
	// feature state, not by a version string.
	var smb1 *bool
	if out, err := runTool(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		"(Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol"); err == nil {
		v := strings.EqualFold(strings.TrimSpace(out), "True")
		smb1 = &v
	}

	// RDP Network Level Authentication: without it, RDP accepts a session
	// before authenticating — the difference between a brute-force target
	// and a hardened one.
	var nla *bool
	if out, err := runTool(ctx, "reg", "query",
		`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`,
		"/v", "UserAuthentication"); err == nil {
		v := strings.Contains(out, "0x1")
		nla = &v
	}

	data := hygieneFacts(listening, poisoning, smb1, nla)
	if len(data) == 0 {
		return nil, run.SkipError{ReasonText: "no hygiene facts could be read on this system"}
	}
	return data, nil
}

// winListeningPorts reuses the sockets collector's table rather than probing.
func winListeningPorts() []int {
	conns, err := winTCPTable()
	if err != nil {
		return nil
	}
	seen := map[int]bool{}
	var out []int
	for _, c := range conns {
		if c.state == 2 && !seen[c.localPort] { // 2 = MIB_TCP_STATE_LISTEN
			seen[c.localPort] = true
			out = append(out, c.localPort)
		}
	}
	return out
}
