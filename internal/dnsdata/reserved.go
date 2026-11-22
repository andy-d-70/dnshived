// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsdata

import (
	"net/netip"
	"slices"
	"sort"

	"dnshived/internal/config"
	"dnshived/internal/dnsanswer"
)

// ReservedName is one DNS name of a DHCP reservation: the hostname or an extra name, as the operator wrote it.
type ReservedName struct {
	Name  string
	IP    netip.Addr
	Scope string
}

// ReservedNames lists the names of every reservation in the order the central dnsmasq published them: scopes by name,
// reservations in their order, the hostname before the extra names. Names or addresses that do not parse are left out.
func ReservedNames(c *config.Cluster) []ReservedName {
	scopes := make([]string, 0, len(c.Scopes))
	for n := range c.Scopes {
		scopes = append(scopes, n)
	}
	sort.Strings(scopes)
	total := 0
	for _, s := range scopes {
		for _, r := range c.Scopes[s].Reservations {
			total += len(r.Names) + 1
		}
	}
	out := make([]ReservedName, 0, total)
	for _, s := range scopes {
		for _, r := range c.Scopes[s].Reservations {
			ip, err := netip.ParseAddr(r.IP)
			if err != nil {
				continue
			}
			ip = ip.Unmap()
			add := func(n string) {
				if name, err := dnsanswer.CanonicalName(n); err == nil {
					out = append(out, ReservedName{Name: name, IP: ip, Scope: s})
				}
			}
			if r.Hostname != "" {
				add(r.Hostname)
			}
			for _, n := range r.Names {
				add(n)
			}
		}
	}
	return out
}

type rrIdent struct {
	owner string
	typ   uint16
	rd    [16]byte
}

func addrIdent(owner string, typ uint16, ip netip.Addr) rrIdent {
	k := rrIdent{owner: owner, typ: typ}
	copy(k.rd[:], ip.AsSlice())
	return k
}

// MergeReserved adds the names of DHCP reservations to spec: an address record for each name, and a reverse record for
// the first name of an address unless the spec already holds a reverse record for it. Reserved names are published
// next to authored ones with the same name, as the central dnsmasq did, and they count as authored for lease names.
func MergeReserved(spec *dnsanswer.Spec, names []ReservedName, ttl uint32) {
	if len(names) == 0 {
		return
	}
	owners := make(map[string]struct{}, len(names)*2)
	revs := make([]string, len(names))
	size := 0
	for i, n := range names {
		revs[i] = dnsanswer.ReverseName(n.IP)
		owners[n.Name] = struct{}{}
		owners[revs[i]] = struct{}{}
		size += n.IP.BitLen() / 8
	}
	have := map[rrIdent]struct{}{}
	rev := map[string]struct{}{}
	for _, rr := range spec.RRs {
		if _, ok := owners[rr.Owner]; !ok {
			continue
		}
		switch rr.Type {
		case dnsanswer.TypeA, dnsanswer.TypeAAAA:
			if ip, ok := netip.AddrFromSlice(rr.RData); ok {
				have[addrIdent(rr.Owner, rr.Type, ip)] = struct{}{}
			}
		case dnsanswer.TypePTR:
			rev[rr.Owner] = struct{}{}
		}
	}
	spec.RRs = slices.Grow(spec.RRs, len(names)*2)
	arena := make([]byte, 0, size)
	for i, n := range names {
		typ := uint16(dnsanswer.TypeA)
		if !n.IP.Is4() {
			typ = dnsanswer.TypeAAAA
		}
		if k := addrIdent(n.Name, typ, n.IP); !hasIdent(have, k) {
			have[k] = struct{}{}
			start := len(arena)
			arena = append(arena, n.IP.AsSlice()...)
			spec.RRs = append(spec.RRs, dnsanswer.RR{Owner: n.Name, Type: typ, TTL: ttl, RData: arena[start:len(arena):len(arena)]})
		}
		if _, ok := rev[revs[i]]; ok {
			continue
		}
		rev[revs[i]] = struct{}{}
		if w, err := dnsanswer.ToWire(n.Name); err == nil {
			spec.RRs = append(spec.RRs, dnsanswer.RR{Owner: revs[i], Type: dnsanswer.TypePTR, TTL: ttl, RData: w})
		}
	}
}

func hasIdent(m map[rrIdent]struct{}, k rrIdent) bool {
	_, ok := m[k]
	return ok
}
