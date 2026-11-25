// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsdata

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"dnshived/internal/dnsanswer"
	"dnshived/internal/dnsstore"
)

// CompileConfig carries what the compilation takes from the cluster configuration.
type CompileConfig struct {
	Zones []dnsanswer.Zone
	// DefaultTTL is the TTL of every row without its own TTL (the store's default_ttl setting).
	DefaultTTL uint32
	NegTTL     uint32
	// Authoritative off marks every zone as forwarded, so only the records held are answered.
	Authoritative bool
}

type RowError struct {
	Type uint8
	ID   dnsstore.ID
	Msg  string
}

// Report lists what the compilation skipped or flagged; a bad row never stops the table from being built.
type Report struct {
	Hosts    int
	Records  int
	Legacy   int
	Dangling []string
	Errors   []RowError
}

func (c *CompileConfig) ttl(own bool, v uint32) uint32 {
	if own || v != 0 {
		return v
	}
	return c.DefaultTTL
}

func join(parts ...string) string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, ".")
}

func canon(s string) (string, error) { return dnsanswer.CanonicalName(s) }

func hostOwners(h *Host, zones map[string]bool, rep *Report, id dnsstore.ID) []string {
	label, err := canon(h.Label)
	if err != nil {
		rep.Errors = append(rep.Errors, RowError{TypeHost, id, "host label: " + errString(err)})
		return nil
	}
	var owners []string
	for _, d := range h.Domains {
		cd, err := canon(d)
		if err != nil || !zones[cd] {
			rep.Dangling = append(rep.Dangling, fmt.Sprintf("%s.%s", h.Label, d))
			continue
		}
		owners = append(owners, label+"."+cd)
	}
	return owners
}

func errString(err error) string {
	if err == nil {
		return "empty"
	}
	return err.Error()
}

// Compile turns the rows of a store view into the spec the relays build their answer table from.
func Compile(v *dnsstore.View, cfg CompileConfig) (*dnsanswer.Spec, Report) {
	var rep Report
	zones := map[string]bool{}
	spec := &dnsanswer.Spec{Serial: uint32(v.Rev()), NegTTL: cfg.NegTTL}
	for _, z := range cfg.Zones {
		if cz, err := canon(z.Name); err == nil {
			zones[cz] = true
			spec.Zones = append(spec.Zones, dnsanswer.Zone{Name: cz, Forward: z.Forward || !cfg.Authoritative})
		}
	}
	add := func(owner string, typ uint16, ttl uint32, rd []byte, err error, t uint8, id dnsstore.ID) {
		if err != nil {
			rep.Errors = append(rep.Errors, RowError{t, id, err.Error()})
			return
		}
		spec.RRs = append(spec.RRs, dnsanswer.RR{Owner: owner, Type: typ, TTL: ttl, RData: rd})
	}
	hosts := map[dnsstore.ID]*Host{}
	var hostIDs []dnsstore.ID
	v.Range(TypeHost, func(id dnsstore.ID, _ uint64, body []byte) bool {
		h, err := DecodeHost(body)
		if err != nil {
			rep.Errors = append(rep.Errors, RowError{TypeHost, id, err.Error()})
			return true
		}
		hosts[id] = &h
		hostIDs = append(hostIDs, id)
		return true
	})
	sort.Slice(hostIDs, func(i, j int) bool { return string(hostIDs[i][:]) < string(hostIDs[j][:]) })
	for _, id := range hostIDs {
		h := hosts[id]
		rep.Hosts++
		owners := hostOwners(h, zones, &rep, id)
		ttl := cfg.ttl(h.OwnTTL, h.TTL)
		var first string
		if len(owners) > 0 {
			first = owners[0]
		}
		for _, o := range owners {
			for _, a := range h.Addrs {
				if a.IP.Is4() || a.IP.Is4In6() {
					rd, err := dnsanswer.RDataA(a.IP.Unmap().String())
					add(o, dnsanswer.TypeA, ttl, rd, err, TypeHost, id)
				} else {
					rd, err := dnsanswer.RDataAAAA(a.IP.String())
					add(o, dnsanswer.TypeAAAA, ttl, rd, err, TypeHost, id)
				}
			}
		}
		if first != "" {
			for _, a := range h.Addrs {
				if a.PTR {
					rd, err := dnsanswer.ToWire(first)
					add(dnsanswer.ReverseName(a.IP), dnsanswer.TypePTR, ttl, rd, err, TypeHost, id)
				}
			}
		}
	}
	var recIDs []dnsstore.ID
	recs := map[dnsstore.ID]Record{}
	v.Range(TypeRecord, func(id dnsstore.ID, _ uint64, body []byte) bool {
		r, err := DecodeRecord(body)
		if err != nil {
			rep.Errors = append(rep.Errors, RowError{TypeRecord, id, err.Error()})
			return true
		}
		recs[id] = r
		recIDs = append(recIDs, id)
		return true
	})
	sort.Slice(recIDs, func(i, j int) bool { return string(recIDs[i][:]) < string(recIDs[j][:]) })
	for _, id := range recIDs {
		r := recs[id]
		rep.Records++
		if r.Type == TypeRAW {
			rep.Legacy++
			continue
		}
		var owners []string
		if r.Host != (dnsstore.ID{}) {
			h := hosts[r.Host]
			if h == nil {
				rep.Errors = append(rep.Errors, RowError{TypeRecord, id, "the host this record belongs to does not exist"})
				continue
			}
			sub := ""
			if r.Sub != "" {
				c, err := canon(r.Sub)
				if err != nil {
					rep.Errors = append(rep.Errors, RowError{TypeRecord, id, "sub-label: " + err.Error()})
					continue
				}
				sub = c
			}
			for _, o := range hostOwners(h, zones, &rep, r.Host) {
				owners = append(owners, join(sub, o))
			}
		} else {
			o, err := canon(r.Owner)
			if err != nil {
				rep.Errors = append(rep.Errors, RowError{TypeRecord, id, "owner: " + err.Error()})
				continue
			}
			owners = []string{o}
		}
		rd, err := recordData(&r)
		for _, o := range owners {
			add(o, r.Type, cfg.ttl(r.OwnTTL, r.TTL), rd, err, TypeRecord, id)
			if err != nil {
				break
			}
		}
	}
	return spec, rep
}

func target(s string) (string, error) { return canon(s) }

func recordData(r *Record) ([]byte, error) {
	switch r.Type {
	case dnsanswer.TypeA:
		return dnsanswer.RDataA(r.Value)
	case dnsanswer.TypeAAAA:
		return dnsanswer.RDataAAAA(r.Value)
	case dnsanswer.TypeCNAME, dnsanswer.TypePTR, dnsanswer.TypeNS:
		t, err := target(r.Value)
		if err != nil {
			return nil, err
		}
		return dnsanswer.ToWire(t)
	case dnsanswer.TypeTXT:
		return dnsanswer.RDataTXT(r.Value)
	case dnsanswer.TypeSRV:
		t, err := target(r.Target)
		if err != nil {
			return nil, err
		}
		return dnsanswer.RDataSRV(r.Prio, r.Weight, r.Port, t)
	case dnsanswer.TypeMX:
		t, err := target(r.Target)
		if err != nil {
			return nil, err
		}
		return dnsanswer.RDataMX(r.Pref, t)
	case dnsanswer.TypeNAPTR:
		repl := ""
		if r.Value != "" {
			t, err := target(r.Value)
			if err != nil {
				return nil, err
			}
			repl = t
		}
		return dnsanswer.RDataNAPTR(r.Order, r.Pref, r.Flags, r.Service, r.Regexp, repl)
	case dnsanswer.TypeCAA:
		return dnsanswer.RDataCAA(r.CAAFlag, r.CAATag, r.Value)
	}
	if r.Raw != "" {
		b, err := hex.DecodeString(r.Raw)
		if err != nil || len(b) == 0 || len(b) > 65535 {
			return nil, fmt.Errorf("record type %d: the data is not valid hex", r.Type)
		}
		return b, nil
	}
	return nil, fmt.Errorf("record type %d is not supported", r.Type)
}
