// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"net"
	"os"
	"testing"

	"dnshived/internal/dhcpprobe"
)

func TestExitCodeForVerdict(t *testing.T) {
	cases := []struct {
		verdict dhcpprobe.Verdict
		want    int
	}{
		{dhcpprobe.VerdictOK, 0},
		{dhcpprobe.VerdictNoAnswer, 1},
		{dhcpprobe.VerdictDualActive, 2},
	}
	for _, c := range cases {
		if got := exitCodeForVerdict(c.verdict); got != c.want {
			t.Errorf("exitCodeForVerdict(%q) = %d, want %d", c.verdict, got, c.want)
		}
	}
}

// TestReport_DNSShownWithoutRouter checks an OFFER with DNS servers
// (option 6) but no router (option 3) still shows its DNS list.
func TestReport_DNSShownWithoutRouter(t *testing.T) {
	result := dhcpprobe.Result{
		Offers: []dhcpprobe.Offer{
			{
				YourIP:   net.IPv4(172, 16, 1, 100),
				ServerID: net.IPv4(172, 16, 1, 1),
				DNS:      []net.IP{net.IPv4(1, 1, 1, 1)},
			},
		},
		Verdict: dhcpprobe.VerdictOK,
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	report(result)
	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()
	if !bytes.Contains([]byte(out), []byte("dns=[1.1.1.1]")) {
		t.Errorf("report() output = %q, want it to include dns=[1.1.1.1] even with no router", out)
	}
}
