// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"dnshived/internal/dhcpprobe"
	"dnshived/internal/dnsprobe"
)

// manualResult is runManualProbe's own report shape.
type manualResult struct {
	Iface string `json:"iface"`
	DHCP  struct {
		WaitMS            int64         `json:"wait_ms"`
		Verdict           string        `json:"verdict,omitempty"`
		Servers           []string      `json:"servers,omitempty"`
		Offers            []manualOffer `json:"offers,omitempty"`
		Error             string        `json:"error,omitempty"`
		DualActiveChecked bool          `json:"dual_active_checked"`
	} `json:"dhcp"`
	DNS *manualDNSResult `json:"dns,omitempty"`
}

type manualOffer struct {
	AtMS     int64  `json:"at_ms"` // arrival time relative to when the DISCOVER was sent
	YourIP   string `json:"your_ip"`
	ServerID string `json:"server_id"`
	Relay    string `json:"relay,omitempty"`
	LeaseSec uint32 `json:"lease_seconds"`
}

type manualDNSResult struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Target    string `json:"target"`
	Answered  bool   `json:"answered"`
	LatencyMS int64  `json:"latency_ms"`
	Data      string `json:"data,omitempty"`
	Error     string `json:"error,omitempty"`
}

// runManualProbe implements -once: a standalone, config-free ad-hoc mode
// so an operator can manually test one VLAN interface's real DHCP/DNS
// behavior.
func runManualProbe(iface string, dhcpWait time.Duration, dnsName, dnsType, dnsTarget string, asJSON, fullWait bool) {
	if iface == "" {
		fmt.Fprintln(os.Stderr, "error: -iface is required with -once")
		os.Exit(1)
	}
	if dnsName != "" && dnsTarget == "" {
		fmt.Fprintln(os.Stderr, "error: -dns-target is required when -dns-name is set")
		os.Exit(1)
	}

	var out manualResult
	out.Iface = iface
	out.DHCP.WaitMS = dhcpWait.Milliseconds()
	out.DHCP.DualActiveChecked = fullWait

	opts := dhcpprobe.DefaultOptions()
	opts.StopOnFirstOffer = !fullWait
	dhcpResult, err := dhcpprobe.ProbeWithOptions(iface, dhcpWait, opts)
	if err != nil {
		out.DHCP.Error = err.Error()
	} else {
		out.DHCP.Verdict = string(dhcpResult.Verdict)
		out.DHCP.Servers = dhcpResult.Servers
		for _, o := range dhcpResult.Offers {
			relay := ""
			if o.GIAddr != nil && !o.GIAddr.Equal(net.IPv4zero) {
				relay = o.GIAddr.String()
			}
			out.DHCP.Offers = append(out.DHCP.Offers, manualOffer{
				AtMS:     o.At.Milliseconds(),
				YourIP:   o.YourIP.String(),
				ServerID: o.ServerID.String(),
				Relay:    relay,
				LeaseSec: o.Lease,
			})
		}
	}

	if dnsName != "" {
		d := &manualDNSResult{Name: dnsName, Type: dnsType, Target: dnsTarget}
		if res, err := dnsprobe.Probe(dnsTarget, dnsName, dnsType, 5*time.Second); err != nil {
			d.Error = err.Error()
		} else {
			d.Answered = res.Answered
			d.LatencyMS = res.Latency.Milliseconds()
			d.Data = res.Data
		}
		out.DNS = d
	}

	if asJSON {
		json.NewEncoder(os.Stdout).Encode(out)
	} else {
		printManualResult(out)
	}

	switch {
	case out.DHCP.Error != "":
		os.Exit(1)
	case out.DHCP.Verdict == string(dhcpprobe.VerdictNoAnswer):
		os.Exit(1)
	case out.DHCP.Verdict == string(dhcpprobe.VerdictDualActive):
		os.Exit(2)
	default:
		os.Exit(0)
	}
}

func printManualResult(out manualResult) {
	fmt.Printf("=== DHCP on %s (wait %dms) ===\n", out.Iface, out.DHCP.WaitMS)
	if out.DHCP.Error != "" {
		fmt.Printf("error: %s\n", out.DHCP.Error)
	} else {
		fmt.Printf("offers received: %d\n", len(out.DHCP.Offers))
		for i, o := range out.DHCP.Offers {
			relay := "none (direct)"
			if o.Relay != "" {
				relay = o.Relay
			}
			fmt.Printf("  #%d  +%-6s yiaddr=%-15s server-id=%-15s relay=%s lease=%ds\n",
				i+1, fmt.Sprintf("%dms", o.AtMS), o.YourIP, o.ServerID, relay, o.LeaseSec)
		}
		fmt.Printf("distinct server-ids: %d %v\n", len(out.DHCP.Servers), out.DHCP.Servers)
		fmt.Printf("verdict: %s\n", out.DHCP.Verdict)
		if !out.DHCP.DualActiveChecked {
			fmt.Println("note: stopped at the first offer — a slower second (rogue) server would not have been seen. Pass -full-wait for a real dual-active check.")
		}
	}
	if out.DNS != nil {
		fmt.Printf("\n=== DNS %s %s against %s ===\n", out.DNS.Name, out.DNS.Type, out.DNS.Target)
		if out.DNS.Error != "" {
			fmt.Printf("error: %s\n", out.DNS.Error)
		} else {
			fmt.Printf("answered: %v  latency: %dms\n", out.DNS.Answered, out.DNS.LatencyMS)
		}
	}
}
