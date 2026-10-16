// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// TestPrintManualResult_ReportsOffersAndDNS pins the human-readable
// report's shape.
func TestPrintManualResult_ReportsOffersAndDNS(t *testing.T) {
	out := manualResult{Iface: "ens19.111"}
	out.DHCP.WaitMS = 9000
	out.DHCP.Verdict = "ok"
	out.DHCP.Servers = []string{"172.16.111.23"}
	out.DHCP.DualActiveChecked = true // suppress the unrelated caveat note for this assertion
	out.DHCP.Offers = []manualOffer{
		{AtMS: 3300, YourIP: "172.16.111.150", ServerID: "172.16.111.23", LeaseSec: 3600},
	}
	out.DNS = &manualDNSResult{Name: "claude.ai.", Type: "A", Target: "172.16.111.23", Answered: true, LatencyMS: 2}

	got := captureStdout(t, func() { printManualResult(out) })

	for _, want := range []string{"ens19.111", "wait 9000ms", "+3300ms", "172.16.111.150", "verdict: ok", "claude.ai.", "answered: true", "latency: 2ms"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q, got:\n%s", want, got)
		}
	}
}

// captureStdout is a small test helper shared by this file's output tests.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, _ := os.Pipe()
	orig := os.Stdout
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = orig
	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

func TestPrintManualResult_NotesIncompleteDualActiveCheck(t *testing.T) {
	out := manualResult{Iface: "ens19.111"}
	out.DHCP.WaitMS = 9000
	out.DHCP.Verdict = "ok"
	out.DHCP.DualActiveChecked = false // the -once default

	got := captureStdout(t, func() { printManualResult(out) })
	if !strings.Contains(got, "stopped at the first offer") {
		t.Errorf("expected a note about the incomplete dual-active check, got:\n%s", got)
	}
}

func TestPrintManualResult_NoNoteWhenFullWaitUsed(t *testing.T) {
	out := manualResult{Iface: "ens19.111"}
	out.DHCP.WaitMS = 9000
	out.DHCP.Verdict = "ok"
	out.DHCP.DualActiveChecked = true // -full-wait was passed

	got := captureStdout(t, func() { printManualResult(out) })
	if strings.Contains(got, "stopped at the first offer") {
		t.Errorf("did not expect the incomplete-check note for a full-wait run, got:\n%s", got)
	}
}

func TestPrintManualResult_ReportsDHCPError(t *testing.T) {
	out := manualResult{Iface: "ens19.111"}
	out.DHCP.WaitMS = 5000
	out.DHCP.Error = "bind :68 on ens19.111: permission denied"

	got := captureStdout(t, func() { printManualResult(out) })

	if !strings.Contains(got, "permission denied") {
		t.Errorf("output missing the DHCP error, got:\n%s", got)
	}
}
