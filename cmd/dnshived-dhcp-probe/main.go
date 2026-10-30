// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// dhcp-probe sends a single DHCPDISCOVER and reports EVERY DHCPOFFER that
// arrives within a listen window — not just the first.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"dnshived/internal/cliguard"
	"dnshived/internal/dhcpprobe"
)

var version = "0.9.7-dev"

func main() {
	iface := flag.String("iface", "", "interface to send from (required)")
	mac := flag.String("mac", "", "client MAC (default: random, locally administered)")
	wait := flag.Duration("wait", 5*time.Second, "how long to listen for offers")
	noBcast := flag.Bool("no-broadcast-flag", false, "clear the BOOTP broadcast flag")
	showVersion := flag.Bool("version", false, "print version and exit")
	cliguard.Parse("dnshived-dhcp-probe", false)

	if *showVersion {
		fmt.Println("dnshived-dhcp-probe", version)
		os.Exit(0)
	}

	if *iface == "" {
		fmt.Fprintln(os.Stderr, "error: --iface is required")
		os.Exit(exitSetupFailure)
	}

	opts := dhcpprobe.DefaultOptions()
	opts.Broadcast = !*noBcast
	if *mac != "" {
		hw, err := net.ParseMAC(*mac)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: parse mac %q: %v\n", *mac, err)
			os.Exit(exitSetupFailure)
		}
		opts.MAC = hw
	}

	fmt.Printf("DISCOVER sending on %s, listening %s\n", *iface, *wait)

	result, err := dhcpprobe.ProbeWithOptions(*iface, *wait, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitSetupFailure)
	}

	report(result)
	os.Exit(exitCodeForVerdict(result.Verdict))
}

// exitSetupFailure is returned when the probe itself never ran.
const exitSetupFailure = 3

// exitCodeForVerdict maps a completed probe's verdict to this binary's
// documented exit code (see the package doc comment).
func exitCodeForVerdict(v dhcpprobe.Verdict) int {
	switch v {
	case dhcpprobe.VerdictNoAnswer:
		return 1
	case dhcpprobe.VerdictDualActive:
		return 2
	default:
		return 0
	}
}

func report(result dhcpprobe.Result) {
	fmt.Printf("\nOFFERs received: %d\n", len(result.Offers))
	for i, o := range result.Offers {
		gi := "none (direct)"
		if o.GIAddr != nil && !o.GIAddr.Equal(net.IPv4zero) {
			gi = o.GIAddr.String()
		}
		fmt.Printf("  #%d  +%-8s yiaddr=%-15s server-id=%-15s relay=%s lease=%ds\n",
			i+1, o.At.Round(time.Millisecond), o.YourIP, o.ServerID, gi, o.Lease)
		if o.Router != nil || len(o.DNS) > 0 {
			fmt.Printf("        router=%v dns=%v\n", o.Router, o.DNS)
		}
	}

	fmt.Printf("\ndistinct server-ids: %d %v\n", len(result.Servers), result.Servers)

	switch result.Verdict {
	case dhcpprobe.VerdictNoAnswer:
		fmt.Println("VERDICT: NO ANSWER — nothing served this segment")
	case dhcpprobe.VerdictDualActive:
		fmt.Println("VERDICT: DUAL-ACTIVE — more than one DHCP server answered")
	default:
		if len(result.Offers) > 1 {
			fmt.Println("VERDICT: OK (one server, duplicate delivery via multiple relays)")
		} else {
			fmt.Println("VERDICT: OK (exactly one server, one path)")
		}
	}
}
