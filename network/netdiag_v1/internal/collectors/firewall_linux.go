//go:build linux

package collectors

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"netdiag/internal/run"
	"netdiag/internal/schema"
)

// ------------------------------------------- local firewall reality (L4, §4.1)

// firewallCollector reads the actual ruleset (nftables first, iptables
// fallback) and reconciles it against the listening sockets: "is it
// dropping the port the app needs". Reading rulesets needs elevation on
// most systems — unprivileged runs skip honestly rather than declaring
// the firewall green.
type firewallCollector struct{}

func (firewallCollector) Name() string      { return "firewall" }
func (firewallCollector) Privilege() string { return schema.PrivElevated }

func (firewallCollector) Collect(ctx context.Context) (map[string]any, error) {
	ruleset, tool, err := readRuleset(ctx)
	if err != nil {
		return nil, err
	}
	data := map[string]any{"firewall_tool": tool}

	// Bug #23 (found while extracting this parser, 0.9.18): the input policy
	// used to DEFAULT to "accept" and only ever be revised to "drop". A
	// ruleset with no filter/input hook at all — an nft config doing only NAT,
	// say — was therefore reported as "input policy accept": a fact nobody
	// measured, printed with the same confidence as one that was. Someone
	// reading that in a ticket concludes the host firewall is wide open.
	//
	// The summarisers report whether the policy was actually STATED. When it
	// was not, the fact is omitted, and every renderer already knows how to
	// show a missing fact as not-measured.
	var sum FirewallSummary
	if tool == "nftables" {
		sum = SummariseNftables(ruleset)
	} else {
		sum = SummariseIptables(ruleset)
	}
	inputPolicy := sum.InputPolicy
	data["firewall_active"] = sum.RuleCount > 0
	data["firewall_rule_count"] = sum.RuleCount
	if inputPolicy != "" {
		data["firewall_input_policy"] = inputPolicy
	}

	// Reconciliation (heuristic tier): with a default-drop input policy,
	// a listening port with no visible accept for it is presumed blocked.
	// Complex rulesets (sets, maps, jumps) exceed this parser — the count
	// is labelled heuristic on purpose.
	if inputPolicy == "drop" || inputPolicy == "reject" {
		blocked := reconcileListeners(ruleset)
		data["firewall_blocked_listeners"] = blocked
		data["firewall_blocked_listener_count"] = len(blocked)
	}
	return data, nil
}

func readRuleset(ctx context.Context) (string, string, error) {
	if _, err := exec.LookPath("nft"); err == nil {
		if out, err := exec.CommandContext(ctx, "nft", "list", "ruleset").Output(); err == nil {
			return string(out), "nftables", nil
		}
	}
	if _, err := exec.LookPath("iptables-save"); err == nil {
		if out, err := exec.CommandContext(ctx, "iptables-save").Output(); err == nil {
			return string(out), "iptables", nil
		}
	}
	if os.Geteuid() != 0 {
		return "", "", run.SkipError{ReasonText: "ruleset not readable unprivileged (elevated tier §3.1) — firewall state is NOT green"}
	}
	return "", "", run.SkipError{ReasonText: "no nft/iptables tooling found to read the ruleset"}
}

// reconcileListeners: naive pass — every listening TCP port either appears
// in an accept rule ("dport <p> accept" / "--dport <p> -j ACCEPT") or is
// flagged. Loopback-only listeners are exempt (input hook irrelevant).
func reconcileListeners(ruleset string) []string {
	low := strings.ToLower(ruleset)
	var blocked []string
	for _, portDesc := range listeningTCPPorts() {
		port, loopback := portDesc.port, portDesc.loopbackOnly
		if loopback {
			continue
		}
		p := strconv.Itoa(port)
		if strings.Contains(low, "dport "+p) || strings.Contains(low, "dport { ") && strings.Contains(low, " "+p+" ") ||
			strings.Contains(low, "--dport "+p) {
			continue // some rule mentions it; assume intentional
		}
		if len(blocked) < 20 {
			blocked = append(blocked, p)
		}
	}
	return blocked
}

type listenPort struct {
	port         int
	loopbackOnly bool
}

func listeningTCPPorts() []listenPort {
	var out []listenPort
	seen := map[int]bool{}
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n")[1:] {
			cols := strings.Fields(line)
			if len(cols) < 4 || cols[3] != "0A" {
				continue
			}
			p := hexPort(cols[1])
			if p == 0 || seen[p] {
				continue
			}
			seen[p] = true
			loop := strings.HasPrefix(cols[1], "0100007F") ||
				strings.HasPrefix(cols[1], "00000000000000000000000001000000")
			out = append(out, listenPort{p, loop})
		}
	}
	return out
}
