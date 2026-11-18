// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package neighbors

import (
	"net/netip"
	"strings"
	"testing"
)

const sample = `IP address       HW type     Flags       HW address            Mask     Device
192.168.2.52     0x1         0x2         bc:24:11:eb:90:22     *        ens19.2
192.168.2.77     0x1         0x0         00:00:00:00:00:00     *        ens19.2
192.168.21.5     0x1         0x2         bc:24:11:aa:00:01     *        ens20.21
garbage line
`

func TestParse(t *testing.T) {
	got, err := Parse(strings.NewReader(sample), "ens19.2")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %+v, want the 2 entries of ens19.2", got)
	}
	if !got[0].Complete || got[0].MAC != "bc:24:11:eb:90:22" {
		t.Errorf("first = %+v", got[0])
	}
	if got[1].Complete || got[1].MAC != "" {
		t.Errorf("an incomplete entry has no MAC: %+v", got[1])
	}
}

func TestCheckTargets(t *testing.T) {
	n := netip.MustParsePrefix("192.168.2.0/24")
	ok := []string{"192.168.2.7", "192.168.2.254"}
	if got, err := CheckTargets(n, ok); err != nil || len(got) != 2 {
		t.Fatalf("valid targets: %v %v", got, err)
	}
	many := make([]string, MaxProbe+1)
	for i := range many {
		many[i] = "192.168.2.9"
	}
	for name, in := range map[string][]string{
		"none":         nil,
		"outside":      {"192.168.3.7"},
		"network addr": {"192.168.2.0"},
		"broadcast":    {"192.168.2.255"},
		"ipv6":         {"fe80::1"},
		"garbage":      {"x"},
		"too many":     many,
	} {
		if _, err := CheckTargets(n, in); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if _, err := CheckTargets(netip.MustParsePrefix("2001:db8::/32"), []string{"192.168.2.7"}); err == nil {
		t.Error("an IPv6 network is refused")
	}
}
