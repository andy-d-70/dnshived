// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net"
	"testing"
)

func TestTrunkParentsFromContent_DropsVLANAndManagementNames(t *testing.T) {
	saved := defaultRouteDevice
	defaultRouteDevice = func() string { return "ens18" }
	t.Cleanup(func() { defaultRouteDevice = saved })

	got := trunkParentsFromContent([]byte(`{"trunk_parents":["ens19","ens19.110","ens18"]}`))
	if len(got) != 1 || !got["ens19"] {
		t.Fatalf("allowlist = %v, want only ens19", got)
	}
}

func TestStaleIPv4Addrs_KeepsWantedAndIPv6(t *testing.T) {
	v4 := func(s string) net.Addr {
		ip, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		n.IP = ip
		return n
	}
	addrs := []net.Addr{
		v4("192.0.2.10/24"),
		v4("192.0.2.99/24"),
		&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
	}
	got := staleIPv4Addrs(addrs, "192.0.2.10/24")
	if len(got) != 1 || got[0] != "192.0.2.99/24" {
		t.Fatalf("stale = %v, want [192.0.2.99/24]", got)
	}
}
