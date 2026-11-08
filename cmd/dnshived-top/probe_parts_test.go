// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import "testing"

func TestProbeCellParts_PendingPartIsDimAndKeepsTheOtherVisible(t *testing.T) {
	pr := probeResult{Enabled: true, DHCPPending: true}
	pr.DNS.Answered = true

	dnsText, dnsColor, dhcpText, dhcpColor := probeCellParts(pr, true, false)

	if dnsText != "DNS✔" || dnsColor != cGreen {
		t.Errorf("dns = %q, want the DNS result shown", dnsText)
	}
	if dhcpText != "DHCP…" || dhcpColor != cYellow {
		t.Errorf("dhcp = %q, want an orange pending marker", dhcpText)
	}
}

func TestProbeCell_PendingPartNeverTurnsTheCellRed(t *testing.T) {
	pr := probeResult{Enabled: true, DNSPending: true}
	pr.DHCP.Verdict = "ok"
	if text, color := probeCell(pr, true); color != cDim || text != "DNS… DHCP✔" {
		t.Errorf("got %q, want a dim cell", text)
	}
}
