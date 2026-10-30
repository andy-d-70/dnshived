// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net"
	"testing"
)

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	ip, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	n.IP = ip.To4()
	return n
}

func TestStaleIPv4(t *testing.T) {
	node := net.ParseIP("10.1.1.2")
	vip := net.ParseIP("10.1.1.254")
	cases := []struct {
		name  string
		addrs []net.Addr
		keep  []net.IP
		want  []string
	}{
		{
			name:  "node and vip kept",
			addrs: []net.Addr{mustCIDR(t, "10.1.1.2/24"), mustCIDR(t, "10.1.1.254/24")},
			keep:  []net.IP{node, vip},
		},
		{
			name:  "unknown address removed",
			addrs: []net.Addr{mustCIDR(t, "10.1.1.2/24"), mustCIDR(t, "10.9.9.9/24")},
			keep:  []net.IP{node, vip},
			want:  []string{"10.9.9.9/24"},
		},
		{
			name:  "vip removed when not kept",
			addrs: []net.Addr{mustCIDR(t, "10.1.1.2/24"), mustCIDR(t, "10.1.1.254/24")},
			keep:  []net.IP{node, nil},
			want:  []string{"10.1.1.254/24"},
		},
		{
			name:  "ipv6 ignored",
			addrs: []net.Addr{&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)}},
			keep:  []net.IP{node, vip},
		},
		{
			name:  "nothing kept removes every ipv4",
			addrs: []net.Addr{mustCIDR(t, "10.1.1.2/24")},
			want:  []string{"10.1.1.2/24"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := staleIPv4(tc.addrs, tc.keep...)
			if len(got) != len(tc.want) {
				t.Fatalf("staleIPv4 = %v, want %v", got, tc.want)
			}
			for i, n := range got {
				if n.String() != tc.want[i] {
					t.Fatalf("staleIPv4[%d] = %s, want %s", i, n, tc.want[i])
				}
			}
		})
	}
}
