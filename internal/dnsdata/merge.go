// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsdata

import (
	"net/netip"
	"sort"
	"strings"

	"dnshived/internal/dnsanswer"
)

type LeaseName struct {
	Name     string
	IP       netip.Addr
	MAC      string
	LeasedAt int64
	Scope    string
}

type Collision struct {
	Name   string
	MAC    string
	Scope  string
	IP     netip.Addr
	Holder string
}

// MergeLeases adds the names of DHCP leases to spec; see LeaseRRs for the rules.
func MergeLeases(spec *dnsanswer.Spec, leases []LeaseName, ttl uint32) []Collision {
	authored := make(map[string]bool, len(spec.RRs))
	for _, rr := range spec.RRs {
		authored[rr.Owner] = true
	}
	rrs, cols := LeaseRRs(func(owner string) bool { return authored[owner] }, leases, ttl)
	spec.RRs = append(spec.RRs, rrs...)
	return cols
}

// LeaseRRs computes the records the names of DHCP leases add. A name is never published twice: an authored name
// (authored reports whether a name has records of its own) always wins, among leases the earliest holder keeps it
// (ties by MAC), and a lease that loses stays without a name and is reported. A holder may publish several addresses
// (for example IPv4 and IPv6) under its name. The owners of the result never have authored records, so the result for
// an owner is the owner's complete record set.
func LeaseRRs(authored func(owner string) bool, leases []LeaseName, ttl uint32) ([]dnsanswer.RR, []Collision) {
	var rrs []dnsanswer.RR
	sorted := append([]LeaseName(nil), leases...)
	sort.Slice(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if (a.LeasedAt == 0) != (b.LeasedAt == 0) {
			return b.LeasedAt == 0
		}
		if a.LeasedAt != b.LeasedAt {
			return a.LeasedAt < b.LeasedAt
		}
		if a.MAC != b.MAC {
			return a.MAC < b.MAC
		}
		if c := a.IP.Compare(b.IP); c != 0 {
			return c < 0
		}
		return a.Name < b.Name
	})
	holder := map[string]string{}
	ptrTaken := map[string]bool{}
	var out []Collision
	for _, l := range sorted {
		name, err := dnsanswer.CanonicalName(l.Name)
		if err != nil || !l.IP.IsValid() || strings.HasPrefix(name, "*") {
			continue
		}
		if authored(name) {
			out = append(out, Collision{Name: name, MAC: l.MAC, Scope: l.Scope, IP: l.IP, Holder: "authored"})
			continue
		}
		if h, ok := holder[name]; ok && h != l.MAC {
			out = append(out, Collision{Name: name, MAC: l.MAC, Scope: l.Scope, IP: l.IP, Holder: h})
			continue
		}
		holder[name] = l.MAC
		ip := l.IP.Unmap()
		var rd []byte
		typ := uint16(dnsanswer.TypeA)
		if ip.Is4() {
			rd, err = dnsanswer.RDataA(ip.String())
		} else {
			typ = dnsanswer.TypeAAAA
			rd, err = dnsanswer.RDataAAAA(ip.String())
		}
		if err != nil {
			continue
		}
		rrs = append(rrs, dnsanswer.RR{Owner: name, Type: typ, TTL: ttl, RData: rd})
		rev := dnsanswer.ReverseName(ip)
		if !authored(rev) && !ptrTaken[rev] {
			ptrTaken[rev] = true
			if w, err := dnsanswer.ToWire(name); err == nil {
				rrs = append(rrs, dnsanswer.RR{Owner: rev, Type: dnsanswer.TypePTR, TTL: ttl, RData: w})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].MAC < out[j].MAC
	})
	return rrs, out
}
