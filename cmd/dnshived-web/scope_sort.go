// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/netip"
	"net/url"
	"sort"
	"strings"
)

// scopeSortCols are the columns of the scope list that can be sorted, in the
// order they appear.
var scopeSortCols = []struct{ Key, Label, Title string }{
	{"scope", "Scope", ""},
	{"worker", "Worker", "the core that serves the scope now"},
	{"interface", "Interface", "the VLAN sub-interface actually constructed on the serving worker's trunk NIC — parent.vlan_id; sorted by interface, then VLAN ID"},
	{"vlan", "VLAN", ""},
	{"subnet", "Subnet", "sorted by network address"},
	{"token", "Token Owner", ""},
	{"status", "Status", "problems first"},
	{"pool", "Pool", "DHCP pool usage — leased addresses out of the scope's own dhcp_range size; fullest first"},
	{"probe", "Probe", "problems first, pending last"},
}

func validScopeSortCol(key string) bool {
	for _, c := range scopeSortCols {
		if c.Key == key {
			return true
		}
	}
	return false
}

// naturalLess orders strings with digit runs by their number, so scope-2 comes
// before scope-10.
func naturalLess(a, b string) bool {
	for a != "" && b != "" {
		ad, bd := a[0] >= '0' && a[0] <= '9', b[0] >= '0' && b[0] <= '9'
		if ad && bd {
			ai, bi := 0, 0
			for ai < len(a) && a[ai] >= '0' && a[ai] <= '9' {
				ai++
			}
			for bi < len(b) && b[bi] >= '0' && b[bi] <= '9' {
				bi++
			}
			an, bn := strings.TrimLeft(a[:ai], "0"), strings.TrimLeft(b[:bi], "0")
			if len(an) != len(bn) {
				return len(an) < len(bn)
			}
			if an != bn {
				return an < bn
			}
			a, b = a[ai:], b[bi:]
			continue
		}
		if a[0] != b[0] {
			return a[0] < b[0]
		}
		a, b = a[1:], b[1:]
	}
	return len(a) < len(b)
}

// statusRank puts problems first.
func statusRank(class string) int {
	switch class {
	case "crit":
		return 0
	case "warn":
		return 1
	case "dim":
		return 2
	default:
		return 3
	}
}

// probeRank is the worst colour among a row's probe cells; a scope no probe
// has answered for yet sorts last.
func probeRank(r scopeRow) int {
	if len(r.ProbeCells) == 0 {
		return 4
	}
	worst := 3
	for _, c := range r.ProbeCells {
		for _, cls := range []string{c.DNSClass, c.DHCPClass} {
			if cls == "" {
				continue
			}
			if rk := statusRank(cls); rk < worst {
				worst = rk
			}
		}
	}
	return worst
}

func subnetKey(cidr string) (netip.Addr, int) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return netip.Addr{}, 0
	}
	return p.Addr(), p.Bits()
}

// sortScopeRows orders rows by col. Ties always fall back to the scope name,
// so the order is stable from one refresh to the next.
func sortScopeRows(rows []scopeRow, col string, desc bool) {
	cmp := func(a, b scopeRow) int {
		switch col {
		case "scope":
			switch {
			case naturalLess(a.Name, b.Name):
				return -1
			case naturalLess(b.Name, a.Name):
				return 1
			}
			return 0
		case "worker":
			return strings.Compare(a.Worker, b.Worker)
		case "interface":
			if a.ParentInterface != b.ParentInterface {
				if naturalLess(a.ParentInterface, b.ParentInterface) {
					return -1
				}
				return 1
			}
			return a.VLANID - b.VLANID
		case "vlan":
			return a.VLANID - b.VLANID
		case "subnet":
			aa, ab := subnetKey(a.Subnet)
			ba, bb := subnetKey(b.Subnet)
			if c := aa.Compare(ba); c != 0 {
				return c
			}
			return ab - bb
		case "token":
			return strings.Compare(a.Token, b.Token)
		case "status":
			return statusRank(a.Class) - statusRank(b.Class)
		case "pool":
			return b.PoolUsagePct - a.PoolUsagePct
		case "probe":
			return probeRank(a) - probeRank(b)
		}
		return 0
	}
	sort.SliceStable(rows, func(i, j int) bool {
		c := cmp(rows[i], rows[j])
		if c != 0 {
			if desc {
				return c > 0
			}
			return c < 0
		}
		return naturalLess(rows[i].Name, rows[j].Name)
	})
}

// sortHeader is one clickable column heading.
type sortHeader struct {
	Label, Title, URL, Arrow, AriaSort string
	Active                             bool
}

// scopeSortHeaders builds the headings. A click sorts by that column
// ascending, a second click reverses it; the arrow sits in a fixed-width slot
// so the heading never moves. Paging and the other query values stay in every
// link.
func scopeSortHeaders(col string, desc bool, keep url.Values, showProbe bool) []sortHeader {
	out := make([]sortHeader, 0, len(scopeSortCols))
	for _, c := range scopeSortCols {
		if c.Key == "probe" && !showProbe {
			continue
		}
		h := sortHeader{Label: c.Label, Title: c.Title, Arrow: " ", AriaSort: "none"}
		q := url.Values{}
		for k, v := range keep {
			q[k] = v
		}
		q.Set("sort", c.Key)
		q.Set("dir", "asc")
		q.Del("page")
		if c.Key == col {
			h.Active = true
			h.AriaSort = "ascending"
			h.Arrow = "▲"
			if desc {
				h.AriaSort, h.Arrow = "descending", "▼"
			} else {
				q.Set("dir", "desc")
			}
		}
		h.URL = "/scopes?" + q.Encode()
		out = append(out, h)
	}
	return out
}
