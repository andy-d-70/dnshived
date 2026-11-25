// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsdata

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"dnshived/internal/config"
	"dnshived/internal/dnsanswer"
	"dnshived/internal/dnsstore"
)

const migrateIDPrefix = "dnshived-dnsstore-import-v2:"

type MigrateReport struct {
	Hosts   int
	Records int
	Skipped []string
	// DomainTTLs lists the local domains whose default TTL no longer applies: their records without an own TTL follow
	// the store's default TTL instead.
	DomainTTLs []string
}

// idMaker derives row ids from the row type and its encoded body, so the same configuration gives the same ids on
// every core and a repeated run changes nothing. It reuses one buffer; it is not safe for concurrent use.
type idMaker struct{ buf []byte }

func (m *idMaker) id(typ uint8, body []byte) dnsstore.ID {
	m.buf = append(append(append(m.buf[:0], migrateIDPrefix...), typ), body...)
	sum := sha256.Sum256(m.buf)
	return dnsstore.ID(sum[:len(dnsstore.ID{})])
}

// recordFromConfig converts one configuration DNS record into a stand-alone record with an absolute owner.
func recordFromConfig(r config.DNSRecord) (Record, error) {
	owner, err := dnsanswer.CanonicalName(r.Name)
	if err != nil {
		return Record{}, err
	}
	rec := Record{Owner: owner, TTL: uint32(max(r.TTL, 0)), ProbeDisabled: r.ProbeDisabled}
	typ := strings.ToUpper(r.Type)
	if typ == "RAW" {
		if r.RRType <= 0 || r.RRType > 65535 || r.RRDataHex == "" {
			return Record{}, fmt.Errorf("a raw record needs a type and data")
		}
		rec.Type, rec.Raw = uint16(r.RRType), strings.ToLower(r.RRDataHex)
	} else {
		code, ok := recordTypeCodes[typ]
		if !ok {
			return Record{}, fmt.Errorf("type %s", r.Type)
		}
		rec.Type = code
		switch typ {
		case "A", "AAAA", "TXT":
			rec.Value = r.Value
		case "CNAME", "PTR":
			v, err := dnsanswer.CanonicalName(r.Value)
			if err != nil {
				return Record{}, fmt.Errorf("target: %v", err)
			}
			rec.Value = v
		case "MX", "SRV", "NAPTR":
			t, err := dnsanswer.CanonicalName(r.Target)
			if err != nil {
				return Record{}, fmt.Errorf("target: %v", err)
			}
			if typ == "NAPTR" {
				rec.Value, rec.Order, rec.Pref = t, uint16(r.NAPTROrder), uint16(r.Priority)
				rec.Flags, rec.Service, rec.Regexp = r.NAPTRFlags, r.NAPTRService, r.NAPTRRegexp
			} else if typ == "MX" {
				rec.Target, rec.Pref = t, uint16(r.Priority)
			} else {
				rec.Target, rec.Prio, rec.Weight, rec.Port = t, uint16(r.Priority), uint16(r.Weight), uint16(r.Port)
			}
		case "CAA":
			rec.Value, rec.CAAFlag, rec.CAATag = r.Value, uint8(r.CAAFlags), r.CAATag
		}
	}
	if _, err := recordData(&rec); err != nil {
		return Record{}, err
	}
	return rec, nil
}

// ConfigRR converts one configuration record into the owner, type and wire data the table answers it with.
func ConfigRR(r config.DNSRecord) (owner string, typ uint16, rdata []byte, err error) {
	rec, err := recordFromConfig(r)
	if err != nil {
		return "", 0, nil, err
	}
	rd, err := recordData(&rec)
	return rec.Owner, rec.Type, rd, err
}

type groupKey struct {
	root, label, ips string
	ttl              uint32
	probe            bool
}

type hostGroup struct {
	label   string
	domains []string
	ips     []netip.Addr
	ttl     uint32
	probe   bool
	done    bool
	claimed map[netip.Addr]bool
}

type domainRef struct {
	canon string
	root  string
	ld    config.LocalDomain
	grp   []*hostGroup
}

// MigrateOps turns the DNS data of a configuration into the rows the store holds: A and AAAA records of the local
// domains become hosts (a linked domain and its original share one host), everything else becomes a record with an
// absolute owner, scope records carry their scope and every record keeps its probe flag. A reverse record is added
// for the first record of an address, as dnsmasq's host-record does. The result depends only on the configuration.
func MigrateOps(c *config.Cluster) ([]dnsstore.Op, MigrateReport) {
	var rep MigrateReport
	byName := map[string]*domainRef{}
	var doms []*domainRef
	for _, d := range c.LocalDomains {
		canon, err := dnsanswer.CanonicalName(d.Name)
		if err != nil {
			rep.Skipped = append(rep.Skipped, fmt.Sprintf("domain %q: %v", d.Name, err))
			continue
		}
		ref := &domainRef{canon: canon, root: canon, ld: d}
		if d.ForkedFrom != "" {
			if p, err := dnsanswer.CanonicalName(d.ForkedFrom); err == nil && p != canon {
				ref.root = p
			}
		}
		byName[canon] = ref
		doms = append(doms, ref)
	}
	for _, d := range doms {
		if _, ok := byName[d.root]; !ok {
			d.root = d.canon
		}
	}

	type labelSet struct {
		idx   []int
		ips   []netip.Addr
		ttl   uint32
		probe bool
		ok    bool
	}
	groups := map[groupKey]*hostGroup{}
	var ipBuf []byte
	for _, d := range doms {
		perLabel := map[string]*labelSet{}
		var order []string
		for i := range d.ld.Records {
			r := &d.ld.Records[i]
			isA, isAAAA := strings.EqualFold(r.Type, "A"), strings.EqualFold(r.Type, "AAAA")
			if !isA && !isAAAA {
				continue
			}
			host := strings.TrimSpace(r.Host)
			if host == "" || host == "@" {
				continue
			}
			label, err := dnsanswer.CanonicalName(host)
			if err != nil {
				continue
			}
			ttl := uint32(max(r.TTL, 0))
			ls := perLabel[label]
			if ls == nil {
				ls = &labelSet{ok: true, ttl: ttl, probe: r.ProbeDisabled}
				perLabel[label] = ls
				order = append(order, label)
			}
			ip, err := netip.ParseAddr(strings.TrimSpace(r.Value))
			if err != nil || ttl != ls.ttl || r.ProbeDisabled != ls.probe || isA != ip.Unmap().Is4() {
				ls.ok = false
				continue
			}
			ls.idx = append(ls.idx, i)
			ls.ips = append(ls.ips, ip.Unmap())
		}
		for _, label := range order {
			ls := perLabel[label]
			if !ls.ok || len(ls.idx) == 0 {
				continue
			}
			slices.SortFunc(ls.ips, func(a, b netip.Addr) int { return a.Compare(b) })
			ls.ips = slices.Compact(ls.ips)
			ipBuf = ipBuf[:0]
			for _, ip := range ls.ips {
				b := ip.As16()
				ipBuf = append(ipBuf, b[:]...)
			}
			key := groupKey{root: d.root, label: label, ips: string(ipBuf), ttl: ls.ttl, probe: ls.probe}
			g := groups[key]
			if g == nil {
				g = &hostGroup{label: label, ips: ls.ips, ttl: ls.ttl, probe: ls.probe}
				groups[key] = g
			}
			g.domains = append(g.domains, d.canon)
			if d.grp == nil {
				d.grp = make([]*hostGroup, len(d.ld.Records))
			}
			for _, i := range ls.idx {
				d.grp[i] = g
			}
		}
	}

	est := len(c.GlobalDNSRecords)
	for _, d := range doms {
		est += len(d.ld.Records)
	}
	for _, sc := range c.Scopes {
		est += len(sc.DNSRecords)
	}
	ops := make([]dnsstore.Op, 0, est+est/8)
	seen := make(map[dnsstore.ID]bool, est+est/8)
	var ids idMaker
	put := func(typ uint8, body []byte) {
		id := ids.id(typ, body)
		if seen[id] {
			return
		}
		seen[id] = true
		ops = append(ops, dnsstore.Op{Kind: dnsstore.OpPut, Type: typ, ID: id, Body: body})
		if typ == TypeHost {
			rep.Hosts++
		} else {
			rep.Records++
		}
	}
	ptrDone := map[netip.Addr]bool{}
	record := func(r config.DNSRecord, scope string) {
		rec, err := recordFromConfig(r)
		if err != nil {
			rep.Skipped = append(rep.Skipped, fmt.Sprintf("%s: %v", r.Name, err))
			return
		}
		rec.Scope = scope
		put(TypeRecord, rec.Encode())
		if rec.Type != dnsanswer.TypeA && rec.Type != dnsanswer.TypeAAAA {
			return
		}
		ip, err := netip.ParseAddr(rec.Value)
		if err != nil || ptrDone[ip.Unmap()] {
			return
		}
		ip = ip.Unmap()
		ptrDone[ip] = true
		ptr := Record{Owner: dnsanswer.ReverseName(ip), Type: dnsanswer.TypePTR, TTL: rec.TTL, Value: rec.Owner, Scope: scope}
		put(TypeRecord, ptr.Encode())
	}

	scopes := make([]string, 0, len(c.Scopes))
	for n := range c.Scopes {
		scopes = append(scopes, n)
	}
	sort.Strings(scopes)
	reserved := map[string][]ReservedName{}
	for _, rn := range ReservedNames(c) {
		reserved[rn.Scope] = append(reserved[rn.Scope], rn)
	}
	for _, n := range scopes {
		for _, r := range c.Scopes[n].DNSRecords {
			record(r, n)
		}
		for _, rn := range reserved[n] {
			ptrDone[rn.IP] = true
		}
	}
	for _, r := range c.GlobalDNSRecords {
		record(r, "")
	}
	var hosts []*hostGroup
	for _, d := range doms {
		for i := range d.ld.Records {
			var g *hostGroup
			if d.grp != nil {
				g = d.grp[i]
			}
			if g == nil {
				er := d.ld.ExpandedRecord(i)
				er.TTL = d.ld.Records[i].TTL
				record(er, "")
				continue
			}
			if ip, err := netip.ParseAddr(strings.TrimSpace(d.ld.Records[i].Value)); err == nil && !ptrDone[ip.Unmap()] {
				ptrDone[ip.Unmap()] = true
				if g.claimed == nil {
					g.claimed = map[netip.Addr]bool{}
				}
				g.claimed[ip.Unmap()] = true
			}
			if !g.done {
				g.done = true
				hosts = append(hosts, g)
			}
		}
	}
	for _, d := range doms {
		if d.ld.TTL <= 0 {
			continue
		}
		n := 0
		for i := range d.ld.Records {
			if d.ld.Records[i].TTL <= 0 {
				n++
			}
		}
		if n > 0 {
			rep.DomainTTLs = append(rep.DomainTTLs, fmt.Sprintf("%s: its default TTL %d no longer applies to %d record(s) without their own TTL; they follow the store's default TTL", d.canon, d.ld.TTL, n))
		}
	}
	for _, g := range hosts {
		h := Host{Label: g.label, Domains: g.domains, TTL: g.ttl, ProbeDisabled: g.probe}
		for _, ip := range g.ips {
			h.Addrs = append(h.Addrs, Addr{IP: ip, PTR: g.claimed[ip]})
		}
		put(TypeHost, h.Encode())
	}
	return ops, rep
}
