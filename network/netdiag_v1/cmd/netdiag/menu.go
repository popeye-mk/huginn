package main

// The guided menu: netdiag for people who do not want to learn verbs.
//
// Every entry maps to exactly the same code path the command line uses — the
// menu is a front door, not a second implementation. It exists because the
// person holding a broken laptop should not have to remember whether the verb
// is `why cant-login` or `why no-login`, and because "I'm lost" is a real
// usability bug, not a user error.

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"netdiag/internal/ref"
)

type menuItem struct {
	label string
	hint  string
	needs string // prompt for an argument, empty when none
	run   func(arg string) int
	group string // heading printed above this item, when it starts a group
}

// menuItems is the table, separated from the loop so the CATALOGUE can be
// tested without a terminal: every entry needs a runner, a label a person can
// recognise, and a prompt that says how to back out. Menu wiring was 0%
// covered when the "-url is silently ignored" class of bug shipped.
func menuItems() []menuItem {
	return []menuItem{
		{group: "SOMETHING IS WRONG", label: "Check this computer's network", hint: "the full check — start here",
			run: func(string) int { return scanCmd(nil) }},
		{label: "I have no internet", hint: "walks L1→L7 and names the first break",
			run: func(string) int { return whyCmd([]string{"no-internet"}) }},
		{label: "Everything is slow", hint: "loss, latency, jitter, DNS timing",
			run: func(string) int { return whyCmd([]string{"slow"}) }},
		{label: "Wi-Fi problems", hint: "signal, channel congestion, roaming, 802.1X",
			run: func(string) int { return whyCmd([]string{"wifi"}) }},
		{label: "It drops now and then", hint: "reads the OS's own event history",
			run: func(string) int { return whyCmd([]string{"intermittent"}) }},

		{label: "I can't reach a server or site", hint: "name or IP, optionally host:port",
			needs: "Which host? (e.g. fileserver, 10.0.0.10, example.com:443)",
			run:   func(arg string) int { return whyCmd([]string{"cant-reach", arg}) }},
		{label: "I can't log in to the domain", hint: "AD: DNS, SRV, ports, clock, trust",
			needs: "Which domain? (e.g. corp.local — Enter to auto-detect)",
			run: func(arg string) int {
				if arg == "" {
					return whyCmd([]string{"cant-login"})
				}
				return whyCmd([]string{"cant-login", arg})
			}},
		{label: "I can't print", hint: "spooler and queue first, then the network path",
			needs: "Printer name or IP?",
			run:   func(arg string) int { return whyCmd([]string{"cant-print", arg}) }},
		{label: "I can't connect with Remote Desktop", hint: "3389 + NLA hints",
			needs: "Which host?",
			run:   func(arg string) int { return whyCmd([]string{"cant-rdp", arg}) }},

		{label: "Watch for a problem that comes and goes", hint: "sits and waits, timestamps the fault",
			group: "WATCH AND COMPARE", needs: "How long? (e.g. 10m, 2h — Enter for 10m)",
			run: func(arg string) int {
				if arg == "" {
					arg = "10m"
				}
				return watchCmd([]string{"-duration", arg})
			}},
		{label: "Remember this place as healthy", hint: "baseline, so later runs can spot drift",
			run: func(string) int { return baselineCmd(nil) }},
		{label: "What changed since it was healthy?", hint: "drift against a saved baseline",
			needs: "Compare with which one? (Enter = newest, or 2, a date, or 7d)",
			run: func(arg string) int {
				if arg == "" {
					return scanCmd([]string{"-diff"})
				}
				return scanCmd([]string{"-diff", "-against", arg})
			}},
		{label: "Show the baselines saved here", hint: "dates of every healthy snapshot kept",
			run: func(string) int { return baselineCmd([]string{"-list"}) }},
		{label: "Compare two machines (working vs broken)", hint: "ranks what differs between two saved snapshots",
			needs: "Two snapshot files? (e.g. good.json bad.json — Enter for how)",
			run: func(arg string) int {
				f := strings.Fields(arg)
				if len(f) != 2 {
					// The workflow spans two machines, so the empty answer gets
					// the recipe rather than an error.
					fmt.Println("  On the WORKING machine:   netdiag -save good.json")
					fmt.Println("  On the BROKEN machine:    netdiag -save bad.json")
					fmt.Println("  Bring both files together, then run this again and type:")
					fmt.Println("      good.json bad.json")
					return 0
				}
				return compareCmd(f)
			}},

		{group: "LOOK AROUND", label: "Who else is on this network?", hint: "devices seen from here, by vendor",
			run: func(string) int { return devicesCmd(nil) }},

		{label: "Test speed and call quality", hint: "USES DATA — bufferbloat grade + delivered speed",
			needs: "What down speed do you pay for, in Mbps? (Enter to skip the comparison)",
			run: func(arg string) int {
				if arg == "" {
					return speedCmd(nil)
				}
				return speedCmd([]string{"-contracted", arg})
			}},

		{group: "HAND IT OVER", label: "Save a report to a file", hint: "HTML you can open, read, or attach to a ticket",
			needs: "File name? (Enter for netdiag-report.html)",
			run: func(arg string) int {
				if arg == "" {
					arg = "netdiag-report.html"
				}
				return scanCmd([]string{"-html", arg})
			}},
		{label: "Explain it in plain language", hint: "no jargon — for the person with the problem",
			run: func(string) int { return scanCmd([]string{"-for-user"}) }},
		{label: "Write a ticket to hand over", hint: "plain text: verdict, evidence, what was ruled out",
			needs: "File name? (Enter to print it here instead)",
			run: func(arg string) int {
				if arg == "" {
					return ticketCmd(nil)
				}
				return ticketCmd([]string{"-o", arg})
			}},
		{group: "TOOLS", label: "Check that netdiag itself is working", hint: "no network — proves the build still reasons correctly",
			run: func(string) int { return selftestCmd(nil) }},
		{label: "Look something up", hint: "ports, subnets, error codes — works offline",
			needs: "What? (e.g. ports, subnets, 3389 — Enter for the index)",
			run: func(arg string) int {
				var args []string
				if arg != "" {
					args = strings.Fields(arg)
				}
				fmt.Print(refLookup(args))
				return 0
			}},
	}
}

func menuCmd() int {
	items := menuItems()

	in := bufio.NewScanner(os.Stdin)
	for {
		fmt.Printf("\nnetdiag %s — what do you want to do?\n", toolVersion)
		fmt.Println(strings.Repeat("─", 72))
		for i, it := range items {
			// Headings turn one long numbered wall into four short lists. The
			// number a person types is unchanged, so anything written down or
			// remembered still works.
			if it.group != "" {
				fmt.Printf("\n  %s\n", it.group)
			}
			fmt.Printf("  %2d. %-42s %s\n", i+1, it.label, dim(it.hint))
		}
		fmt.Println("\n   0. Back      q. Quit      (or type part of a name, e.g. \"print\")")
		fmt.Print("\nChoose: ")

		if !in.Scan() {
			return 0
		}
		choice := strings.ToLower(strings.TrimSpace(in.Text()))
		switch choice {
		case "q", "quit", "exit":
			return 0
		case "0", "b", "back", "":
			// Already at the top level: 0 has nowhere further back to go, so
			// say that rather than silently quitting — an accidental 0 must
			// never drop someone out of the program.
			fmt.Println("  You are at the main menu. Press q to quit.")
			continue
		}
		idx := 0
		if _, err := fmt.Sscanf(choice, "%d", &idx); err != nil || idx < 1 || idx > len(items) {
			// Not a number: treat it as a search. "print" should find the
			// printing check without the person counting rows.
			matches := matchItems(items, choice)
			switch len(matches) {
			case 1:
				idx = matches[0] + 1
			case 0:
				fmt.Printf("  Nothing matches %q — type a number, 0 to go back, or q to quit.\n", choice)
				continue
			default:
				fmt.Println("  Did you mean:")
				for _, m := range matches {
					fmt.Printf("   %2d. %s\n", m+1, items[m].label)
				}
				continue
			}
		}
		it := items[idx-1]

		arg := ""
		if it.needs != "" {
			fmt.Printf("  %s\n  (0 = back to the menu)\n  > ", it.needs)
			if in.Scan() {
				arg = strings.TrimSpace(in.Text())
			}
			if l := strings.ToLower(arg); l == "0" || l == "b" || l == "back" {
				continue // changed their mind — no harm done, nothing ran
			}
			// Only the checks that genuinely cannot run without a target
			// insist; the rest treat empty as "use the default".
			if arg == "" &&
				(strings.HasPrefix(it.needs, "Which host") || strings.HasPrefix(it.needs, "Printer")) {
				fmt.Println("  Nothing to check without a target — back to the menu.")
				continue
			}
		}
		fmt.Println()
		it.run(arg)

		for {
			fmt.Print("\n  0 = main menu   r = run this again   q = quit  > ")
			if !in.Scan() {
				return 0
			}
			switch strings.ToLower(strings.TrimSpace(in.Text())) {
			case "q", "quit", "exit":
				return 0
			case "r", "again":
				fmt.Println()
				it.run(arg)
				continue
			default: // 0, Enter, or anything else returns to the menu
			}
			break
		}
	}
}

// matchItems finds entries whose label or hint contains q. Typing "print" or
// "slow" is what people actually do when a list gets long; making them count
// rows is the kind of small friction that stops a tool being picked up.
func matchItems(items []menuItem, q string) []int {
	var out []int
	for i, it := range items {
		if strings.Contains(strings.ToLower(it.label), q) ||
			strings.Contains(strings.ToLower(it.hint), q) {
			out = append(out, i)
		}
	}
	return out
}

// dim keeps the hint visually secondary without requiring colour support
// (Windows consoles vary; parentheses always render).
func dim(s string) string {
	if s == "" {
		return ""
	}
	return "(" + s + ")"
}

// refLookup keeps the menu's dependency on the ref package in one place.
func refLookup(args []string) string { return ref.Lookup(args) }
