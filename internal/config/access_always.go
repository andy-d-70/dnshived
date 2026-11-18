// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package config

import (
	"net"
	"net/netip"
	"sort"
	"strings"
)

// AccessAlways lists the addresses the access list serves no matter what, so the cluster can never cut itself off:
// every scope's VIP, gateway and node addresses (including per-node overrides), the management VIP, and the peers.
// The result is sorted and has no duplicates.
func (c *Cluster) AccessAlways() []string {
	if c.AccessAlwaysFrom != nil {
		return append([]string(nil), c.AccessAlwaysFrom...)
	}
	seen := map[netip.Addr]bool{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if i := strings.IndexByte(s, '/'); i >= 0 {
			s = s[:i]
		}
		if host, _, err := net.SplitHostPort(s); err == nil {
			s = host
		}
		if a, err := netip.ParseAddr(s); err == nil {
			seen[a.Unmap()] = true
		}
	}
	for _, sc := range c.Scopes {
		add(sc.VIP)
		add(sc.NodeIP)
		add(sc.Gateway)
		for _, ip := range sc.NodeIPOverrides {
			add(ip)
		}
	}
	if c.MgmtVIP != nil {
		add(c.MgmtVIP.VIP)
	}
	add(c.ControlAddr)
	add(c.BindAddr)
	for _, p := range c.Peers {
		add(p)
	}
	out := make([]string, 0, len(seen))
	for a := range seen {
		out = append(out, a.String())
	}
	sort.Strings(out)
	return out
}
