// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsdata

import (
	"fmt"
	"sort"
	"strings"

	"dnshived/internal/dnsanswer"
	"dnshived/internal/dnsstore"
)

const (
	DefaultMaxNames = 250000
	maxCNAMEHops    = 16
	minTTLWarn      = 120
	maxTTLWarn      = 7 * 24 * 3600
)

// GateContext is what the write gate reads from outside the store.
type GateContext struct {
	Zones       map[string]bool
	Reserved    map[string]string
	LeaseHolder func(name string) (holder string, ok bool)
	MaxNames    int
	AllowLegacy bool
}

type Warning struct {
	Code  string
	Owner string
	Msg   string
}

type Verdict struct {
	Errors   []string
	Warnings []Warning
}

func (v *Verdict) OK() bool { return len(v.Errors) == 0 }

func (v *Verdict) errf(format string, a ...any) {
	v.Errors = append(v.Errors, fmt.Sprintf(format, a...))
}

type nameEntry struct {
	hosts  []dnsstore.ID
	types  map[uint16][]dnsstore.ID
	target string
}

type state struct {
	hosts   map[dnsstore.ID]Host
	records map[dnsstore.ID]Record
	names   map[string]*nameEntry
	owners  int
}

func (s *state) entry(n string) *nameEntry {
	e := s.names[n]
	if e == nil {
		e = &nameEntry{types: map[uint16][]dnsstore.ID{}}
		s.names[n] = e
	}
	return e
}

func hostNames(h *Host) []string {
	label, err := dnsanswer.CanonicalName(h.Label)
	if err != nil {
		return nil
	}
	var out []string
	for _, d := range h.Domains {
		if cd, err := dnsanswer.CanonicalName(d); err == nil {
			out = append(out, label+"."+cd)
		}
	}
	return out
}

func recordNames(r *Record, hosts map[dnsstore.ID]Host) []string {
	if r.Host == (dnsstore.ID{}) {
		if o, err := dnsanswer.CanonicalName(r.Owner); err == nil {
			return []string{o}
		}
		return nil
	}
	h, ok := hosts[r.Host]
	if !ok {
		return nil
	}
	sub := ""
	if r.Sub != "" {
		c, err := dnsanswer.CanonicalName(r.Sub)
		if err != nil {
			return nil
		}
		sub = c
	}
	var out []string
	for _, n := range hostNames(&h) {
		out = append(out, join(sub, n))
	}
	return out
}

func buildState(v *dnsstore.View, ops []dnsstore.Op, verdict *Verdict) *state {
	s := &state{hosts: map[dnsstore.ID]Host{}, records: map[dnsstore.ID]Record{}, names: map[string]*nameEntry{}}
	touched := map[dnsstore.ID]bool{}
	for _, op := range ops {
		touched[op.ID] = true
	}
	load := func(typ uint8, id dnsstore.ID, body []byte) {
		switch typ {
		case TypeHost:
			if h, err := DecodeHost(body); err == nil {
				s.hosts[id] = h
			} else if touched[id] {
				verdict.errf("host %x: %v", id[:4], err)
			}
		case TypeRecord:
			if r, err := DecodeRecord(body); err == nil {
				s.records[id] = r
			} else if touched[id] {
				verdict.errf("record %x: %v", id[:4], err)
			}
		}
	}
	for _, typ := range []uint8{TypeHost, TypeRecord} {
		v.Range(typ, func(id dnsstore.ID, _ uint64, body []byte) bool {
			if !touched[id] {
				load(typ, id, body)
			}
			return true
		})
	}
	for _, op := range ops {
		if op.Kind != dnsstore.OpPut {
			continue
		}
		if op.Type == TypeSetting {
			switch key, _ := SettingKey(op.ID); key {
			case AuthoritativeKey:
				if string(op.Body) != "0" && string(op.Body) != "1" {
					verdict.errf("the cutover setting is 0 or 1")
				}
			default:
				verdict.errf("unknown setting")
			}
			continue
		}
		if op.Type != TypeHost && op.Type != TypeRecord {
			verdict.errf("row type %d is not a DNS row", op.Type)
			continue
		}
		load(op.Type, op.ID, op.Body)
	}
	for id, h := range s.hosts {
		h := h
		names := hostNames(&h)
		s.owners += len(names)
		for _, n := range names {
			e := s.entry(n)
			e.hosts = append(e.hosts, id)
			if len(h.Addrs) > 0 {
				e.types[dnsanswer.TypeA] = append(e.types[dnsanswer.TypeA], id)
			}
		}
	}
	for id, r := range s.records {
		r := r
		for _, n := range recordNames(&r, s.hosts) {
			e := s.entry(n)
			e.types[r.Type] = append(e.types[r.Type], id)
			if r.Type == dnsanswer.TypeCNAME {
				if t, err := dnsanswer.CanonicalName(r.Value); err == nil {
					e.target = t
				}
			}
		}
	}
	return s
}

func ttlCheck(verdict *Verdict, owner string, ttl uint32) {
	switch {
	case ttl > maxTTL:
		verdict.errf("%s: ttl %d is above %d", owner, ttl, maxTTL)
	case ttl != 0 && ttl < minTTLWarn:
		verdict.Warnings = append(verdict.Warnings, Warning{"short-ttl", owner, "a ttl below two minutes is meant for debugging only"})
	case ttl > maxTTLWarn:
		verdict.Warnings = append(verdict.Warnings, Warning{"long-ttl", owner, "a ttl above seven days delays every later change"})
	}
}

// Validate checks a batch of DNS row operations against the store view and the outside context before it is committed.
func Validate(v *dnsstore.View, ops []dnsstore.Op, ctx GateContext) Verdict {
	var verdict Verdict
	if ctx.MaxNames == 0 {
		ctx.MaxNames = DefaultMaxNames
	}
	st := buildState(v, ops, &verdict)
	if st.owners > ctx.MaxNames {
		verdict.errf("%d names after expanding the domains, the limit is %d: forward the extra domains to another server", st.owners, ctx.MaxNames)
	}
	deleted := map[dnsstore.ID]bool{}
	for _, op := range ops {
		if op.Kind == dnsstore.OpDel && op.Type == TypeSetting {
			verdict.errf("a setting cannot be removed")
			continue
		}
		if op.Kind == dnsstore.OpDel {
			deleted[op.ID] = true
		}
	}
	for _, op := range ops {
		switch {
		case op.Kind == dnsstore.OpDel && op.Type == TypeHost:
			for rid, r := range st.records {
				if r.Host == op.ID && !deleted[rid] {
					verdict.errf("host %x still has records; delete them in the same change", op.ID[:4])
					break
				}
			}
		case op.Kind == dnsstore.OpPut && op.Type == TypeHost:
			if h, ok := st.hosts[op.ID]; ok {
				checkHost(&verdict, st, op.ID, &h, ctx)
			}
		case op.Kind == dnsstore.OpPut && op.Type == TypeRecord:
			if r, ok := st.records[op.ID]; ok {
				checkRecord(&verdict, st, op.ID, &r, ctx)
			}
		}
	}
	sort.Slice(verdict.Warnings, func(i, j int) bool {
		return verdict.Warnings[i].Owner+verdict.Warnings[i].Code < verdict.Warnings[j].Owner+verdict.Warnings[j].Code
	})
	return verdict
}

func checkHost(verdict *Verdict, st *state, id dnsstore.ID, h *Host, ctx GateContext) {
	label, err := dnsanswer.CanonicalName(h.Label)
	if err != nil {
		verdict.errf("host label %q: %v", h.Label, err)
		return
	}
	if len(h.Domains) == 0 {
		verdict.errf("host %s needs at least one domain", label)
	}
	seen := map[string]bool{}
	for _, d := range h.Domains {
		cd, err := dnsanswer.CanonicalName(d)
		if err != nil {
			verdict.errf("host %s: domain %q: %v", label, d, err)
			continue
		}
		if seen[cd] {
			verdict.errf("host %s lists %s twice", label, cd)
		}
		seen[cd] = true
		if !ctx.Zones[cd] {
			verdict.errf("host %s: the domain %s is not in the domain list", label, cd)
		}
	}
	ttlCheck(verdict, label, h.TTL)
	for _, a := range h.Addrs {
		if !a.IP.IsValid() || a.IP.IsUnspecified() || a.IP.IsMulticast() {
			verdict.errf("host %s: address %v is not usable", label, a.IP)
		}
	}
	for _, n := range hostNames(h) {
		e := st.names[n]
		if e == nil {
			continue
		}
		for _, other := range e.hosts {
			if other != id {
				verdict.errf("%s is already used by another host", n)
				break
			}
		}
		if len(e.types[dnsanswer.TypeCNAME]) > 0 && len(h.Addrs) > 0 {
			verdict.errf("%s is an alias (CNAME) and cannot also have addresses", n)
		}
		if who, ok := ctx.Reserved[n]; ok {
			verdict.errf("%s is the name of the reservation %s", n, who)
		}
		if ctx.LeaseHolder != nil {
			if who, ok := ctx.LeaseHolder(n); ok {
				verdict.Warnings = append(verdict.Warnings, Warning{"lease-holds-name", n, "the DHCP lease of " + who + " publishes this name; it loses the name when this change is committed"})
			}
		}
	}
}

func checkRecord(verdict *Verdict, st *state, id dnsstore.ID, r *Record, ctx GateContext) {
	if r.Type == TypeRAW {
		if !ctx.AllowLegacy {
			verdict.errf("raw records cannot be added; use a typed record")
		}
		return
	}
	if r.Host != (dnsstore.ID{}) {
		if _, ok := st.hosts[r.Host]; !ok {
			verdict.errf("a record belongs to a host that does not exist")
			return
		}
	} else if r.Owner == "" {
		verdict.errf("a record needs an owner name or a host")
		return
	}
	names := recordNames(r, st.hosts)
	if len(names) == 0 {
		verdict.errf("record owner %q is not a valid name", r.Owner)
		return
	}
	if _, err := recordData(r); err != nil {
		verdict.errf("%s: %v", names[0], err)
		return
	}
	ttlCheck(verdict, names[0], r.TTL)
	for _, n := range names {
		e := st.names[n]
		if e == nil {
			continue
		}
		if r.Type == dnsanswer.TypeCNAME {
			if len(e.types[dnsanswer.TypeCNAME]) > 1 {
				verdict.errf("%s has more than one CNAME", n)
			}
			for typ, ids := range e.types {
				if typ != dnsanswer.TypeCNAME && len(ids) > 0 {
					verdict.errf("%s is an alias (CNAME) and cannot also have other records", n)
					break
				}
			}
			if cycle(st, n) {
				verdict.errf("%s: the CNAME chain leads back to itself", n)
			}
			if t, err := dnsanswer.CanonicalName(r.Value); err == nil && st.names[t] == nil && underZone(t, ctx.Zones) {
				verdict.Warnings = append(verdict.Warnings, Warning{"dangling-cname", n, "the target " + t + " does not exist yet"})
			}
		} else if len(e.types[dnsanswer.TypeCNAME]) > 0 {
			verdict.errf("%s is an alias (CNAME) and cannot also have other records", n)
		}
		if who, ok := ctx.Reserved[n]; ok && (r.Type == dnsanswer.TypeA || r.Type == dnsanswer.TypeAAAA || r.Type == dnsanswer.TypeCNAME) {
			verdict.errf("%s is the name of the reservation %s", n, who)
		}
	}
}

func cycle(st *state, start string) bool {
	n := start
	for i := 0; i < maxCNAMEHops; i++ {
		e := st.names[n]
		if e == nil || e.target == "" {
			return false
		}
		n = e.target
		if n == start {
			return true
		}
	}
	return true
}

func underZone(name string, zones map[string]bool) bool {
	for n := name; ; {
		if zones[n] {
			return true
		}
		i := strings.IndexByte(n, '.')
		if i < 0 {
			return false
		}
		n = n[i+1:]
	}
}
