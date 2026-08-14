package main

// `netdiag devices` — who else is on this network (§4.2/§11/§12).
//
// Passive by default: it reads the neighbour table this machine already has,
// which costs nothing and touches nobody. The active sweep is behind
// --authorized AND a typed confirmation, because pinging a whole subnet
// contacts other people's machines — harmless in itself, but not something a
// tool should do because someone pressed a menu number by accident.

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"netdiag/internal/collectors"
	"netdiag/internal/discover"
	"netdiag/internal/run"
)

func devicesCmd(args []string) int {
	fs := flag.NewFlagSet("devices", flag.ExitOnError)
	authorized := fs.Bool("authorized", false, "permit the active ping sweep of the local subnet (§3)")
	subnet := fs.String("subnet", "", "which CIDR to sweep (default: this machine's own subnet)")
	jsonOut := fs.Bool("json", false, "emit the inventory as JSON")
	yes := fs.Bool("yes", false, "skip the typed confirmation (scripts; still requires -authorized)")
	saveAs := fs.String("save", "", "write the inventory to a file (for later comparison)")
	since := fs.String("since", "", "compare against a saved inventory and list what is NEW")
	_ = fs.Parse(args)

	// Context for the passive read: gateway + own addresses give the roles.
	snap := run.Only(collectors.ForThisOS(), []string{"routing", "addressing"}, toolVersion)
	facts := snap.Facts()
	gateway, _ := facts["gateway_ip"].(string)
	var ownIPs []string
	switch v := facts["ipv4_addresses"].(type) {
	case []string:
		ownIPs = v
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok {
				ownIPs = append(ownIPs, s)
			}
		}
	}

	inv := discover.FromNeighbours(collectors.NeighbourTable(), gateway, ownIPs)

	if *authorized {
		cidr := *subnet
		if cidr == "" {
			cidr = pickLocalSubnet(ownIPs)
		}
		if cidr == "" {
			fmt.Fprintln(os.Stderr, "  Could not work out this machine's subnet — pass -subnet 192.168.1.0/24")
			return 2
		}
		hosts, err := discover.HostsIn(cidr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "  Refusing to sweep:", err)
			return 2
		}
		fmt.Println(discover.AuthorizationText(cidr, len(hosts)))
		if !*yes {
			fmt.Print("\n  Type 'yes' to continue: ")
			in := bufio.NewScanner(os.Stdin)
			if !in.Scan() || strings.TrimSpace(strings.ToLower(in.Text())) != "yes" {
				fmt.Println("  Cancelled — nothing was sent.")
				return 0
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		go func() { <-sig; cancel() }()

		fmt.Printf("\n  sweeping %s (%d addresses) …\n", cidr, len(hosts))
		alive := discover.Sweep(ctx, hosts, collectors.ProbeICMP, 32)
		fmt.Printf("  %d answered; re-reading the neighbour table …\n\n", len(alive))

		// The sweep's real value: it populates the ARP table, so the passive
		// read now sees MACs (and therefore vendors) for everything that
		// answered — and for some things that did not.
		inv = discover.FromNeighbours(collectors.NeighbourTable(), gateway, ownIPs)
		inv.Active = true
		inv.Subnet = cidr
		inv.SweptHost = len(hosts)
		respond := map[string]bool{}
		for _, ip := range alive {
			respond[ip] = true
		}
		for i := range inv.Devices {
			inv.Devices[i].Responded = respond[inv.Devices[i].IP]
		}
	}

	if *jsonOut {
		b, _ := json.MarshalIndent(inv, "", "  ")
		fmt.Println(string(b))
	} else {
		fmt.Printf("netdiag %s — devices on this network\n", toolVersion)
		fmt.Println(strings.Repeat("─", 72) + "\n")
		fmt.Print(inv.Render())
		if !*authorized {
			fmt.Println("\n  To probe the whole subnet (contacts other machines — only on a network")
			fmt.Println("  you administer): netdiag devices -authorized")
		}
	}

	// Arrivals since a saved inventory: the shadow-IT question.
	if *since != "" {
		b, err := os.ReadFile(*since)
		if err != nil {
			fmt.Fprintln(os.Stderr, "  could not read the saved inventory:", err)
		} else {
			var old discover.Inventory
			if err := json.Unmarshal(b, &old); err != nil {
				fmt.Fprintln(os.Stderr, "  saved inventory is not readable:", err)
			} else if newOnes := discover.NewSince(old, inv); len(newOnes) > 0 {
				fmt.Printf("\n  NEW since %s (%d):\n", old.At.Local().Format("2006-01-02 15:04"), len(newOnes))
				for _, d := range newOnes {
					v := d.Vendor
					if v == "" {
						v = "unknown vendor"
					}
					fmt.Printf("   • %-15s %-17s %s\n", d.IP, d.MAC, v)
				}
				fmt.Println("   → confirm each of these belongs here.")
			} else {
				fmt.Println("\n  No new devices since that inventory was saved.")
			}
		}
	}
	if *saveAs != "" {
		b, _ := json.MarshalIndent(inv, "", "  ")
		if err := os.WriteFile(*saveAs, b, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "  save error:", err)
		} else {
			fmt.Printf("\n  Inventory saved to %s — compare later with:\n"+
				"    netdiag devices -since %s\n", *saveAs, *saveAs)
		}
	}
	return 0
}

// pickLocalSubnet turns this machine's address into the CIDR it sits on.
func pickLocalSubnet(ownIPs []string) string {
	for _, cidr := range collectors.LocalSubnets() {
		ip, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		for _, own := range ownIPs {
			if ip.String() == own || ipnet.Contains(net.ParseIP(own)) {
				return ipnet.String()
			}
		}
	}
	return ""
}
