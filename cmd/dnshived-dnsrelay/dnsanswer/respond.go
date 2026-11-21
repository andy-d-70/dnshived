// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsanswer

import "encoding/binary"

type Status int

const (
	Forward Status = iota
	Answered
)

const (
	TypeA     = 1
	TypeCNAME = 5
	TypeIXFR  = 251
	TypeAXFR  = 252
	TypeANY   = 255
	MaxUDP    = 1232
	maxChain  = 8
)

const (
	rForward uint8 = iota
	rAnswer
	rNoData
	rNXDomain
	rRefuse
)

var be = binary.BigEndian

type query struct {
	flags     uint16
	nameStart int
	nameEnd   int
	qEnd      int
	qtype     uint16
	qclass    uint16
	hasOPT    bool
	optSize   uint16
}

func skipRRName(q []byte, off int) (int, bool) {
	for i := 0; i < 128; i++ {
		if off >= len(q) {
			return 0, false
		}
		b := q[off]
		switch {
		case b == 0:
			return off + 1, true
		case b&0xC0 == 0xC0:
			if off+2 > len(q) {
				return 0, false
			}
			return off + 2, true
		case b&0xC0 != 0:
			return 0, false
		default:
			off += 1 + int(b)
		}
	}
	return 0, false
}

func parseQuery(q []byte) (query, bool) {
	var p query
	if len(q) < 12 {
		return p, false
	}
	p.flags = be.Uint16(q[2:])
	if p.flags&0x8000 != 0 || (p.flags>>11)&0xF != 0 {
		return p, false
	}
	if be.Uint16(q[4:]) != 1 || be.Uint16(q[6:]) != 0 || be.Uint16(q[8:]) != 0 {
		return p, false
	}
	ar := int(be.Uint16(q[10:]))
	if ar > 8 {
		return p, false
	}
	off := 12
	p.nameStart = off
	for {
		if off >= len(q) {
			return p, false
		}
		n := int(q[off])
		if n == 0 {
			off++
			break
		}
		if n&0xC0 != 0 {
			return p, false
		}
		off += 1 + n
		if off-12 > 255 {
			return p, false
		}
	}
	p.nameEnd = off
	if off+4 > len(q) {
		return p, false
	}
	p.qtype = be.Uint16(q[off:])
	p.qclass = be.Uint16(q[off+2:])
	p.qEnd = off + 4
	off = p.qEnd
	for i := 0; i < ar; i++ {
		var ok bool
		if off, ok = skipRRName(q, off); !ok || off+10 > len(q) {
			return p, false
		}
		typ, class, ttl, rdl := be.Uint16(q[off:]), be.Uint16(q[off+2:]), be.Uint32(q[off+4:]), int(be.Uint16(q[off+8:]))
		off += 10
		if off+rdl > len(q) {
			return p, false
		}
		if typ == 41 {
			if p.hasOPT || (ttl>>16)&0xFF != 0 {
				return p, false
			}
			p.hasOPT, p.optSize = true, class
		}
		off += rdl
	}
	return p, true
}

type result struct {
	kind uint8
	g    int
	wild bool
	apex int
}

func labelOffsets(qw []byte, offs *[128]uint8) int {
	n := 0
	for off := 0; off < len(qw) && qw[off] != 0 && n < len(offs); off += 1 + int(qw[off]) {
		offs[n] = uint8(off)
		n++
	}
	return n
}

func (t *Table) resolve(qw []byte) result {
	if g := t.find(qw); g >= 0 && t.groups[g].nRR > 0 {
		return result{kind: rAnswer, g: g, apex: -1}
	}
	var offs [128]uint8
	n := labelOffsets(qw, &offs)
	zi, zg := -1, -1
	for i := 0; i < n; i++ {
		if g := t.find(qw[offs[i]:]); g >= 0 && t.groups[g].flags&flagZone != 0 {
			zi, zg = i, g
			break
		}
	}
	if zi < 0 || t.groups[zg].flags&flagFwd != 0 {
		return result{kind: rForward}
	}
	if g := t.find(qw); g >= 0 {
		return result{kind: rNoData, apex: zg}
	}
	var wc [258]byte
	for i := 1; i <= zi; i++ {
		if t.find(qw[offs[i]:]) < 0 {
			continue
		}
		wc[0], wc[1] = 1, '*'
		w := append(wc[:2], qw[offs[i]:]...)
		if g := t.find(w); g >= 0 && t.groups[g].nRR > 0 {
			return result{kind: rAnswer, g: g, wild: true, apex: zg}
		}
		break
	}
	return result{kind: rNXDomain, apex: zg}
}

func (t *Table) zoneApex(qw []byte) int {
	var offs [128]uint8
	n := labelOffsets(qw, &offs)
	for i := 0; i < n; i++ {
		if g := t.find(qw[offs[i]:]); g >= 0 && t.groups[g].flags&flagZone != 0 {
			if t.groups[g].flags&flagFwd != 0 {
				return -1
			}
			return g
		}
	}
	return -1
}

func (t *Table) emit(out []byte, name []byte, r rrEnt) []byte {
	if name == nil {
		out = append(out, 0xC0, 0x0C)
	} else {
		out = append(out, name...)
	}
	out = be.AppendUint16(out, r.typ)
	out = be.AppendUint16(out, 1)
	out = be.AppendUint32(out, r.ttl)
	out = be.AppendUint16(out, r.rdLen)
	return append(out, t.arena[r.rdOff:r.rdOff+uint32(r.rdLen)]...)
}

func (t *Table) groupRRs(g *group) []rrEnt { return t.rrs[g.firstRR : g.firstRR+uint32(g.nRR)] }

// writeAnswer appends the records for qtype at group gi (following CNAMEs inside the table) and counts them.
func (t *Table) writeAnswer(out []byte, gi int, qtype uint16, an *int) []byte {
	g := &t.groups[gi]
	rrs := t.groupRRs(g)
	if qtype == TypeANY && len(rrs) > 0 {
		first := rrs[0].typ
		for _, r := range rrs {
			if r.typ == first {
				out = t.emit(out, nil, r)
				*an++
			}
		}
		return out
	}
	start := *an
	for _, r := range rrs {
		if r.typ == qtype {
			out = t.emit(out, nil, r)
			*an++
		}
	}
	if *an > start || qtype == TypeCNAME {
		return out
	}
	var cn *rrEnt
	for i := range rrs {
		if rrs[i].typ == TypeCNAME {
			cn = &rrs[i]
			break
		}
	}
	if cn == nil {
		return out
	}
	out = t.emit(out, nil, *cn)
	*an++
	for hop := 0; hop < maxChain; hop++ {
		target := t.arena[cn.rdOff : cn.rdOff+uint32(cn.rdLen)]
		ti := t.find(target)
		if ti < 0 {
			break
		}
		tg := &t.groups[ti]
		trrs := t.groupRRs(tg)
		found := false
		for _, r := range trrs {
			if r.typ == qtype || qtype == TypeANY && r.typ == trrs[0].typ {
				out = t.emit(out, t.name(tg), r)
				*an++
				found = true
			}
		}
		if found {
			break
		}
		cn = nil
		for i := range trrs {
			if trrs[i].typ == TypeCNAME {
				cn = &trrs[i]
				break
			}
		}
		if cn == nil {
			break
		}
		out = t.emit(out, t.name(tg), *cn)
		*an++
	}
	return out
}

func (t *Table) writeSOA(out []byte, apex int) []byte {
	name := t.name(&t.groups[apex])
	out = append(out, name...)
	out = be.AppendUint16(out, 6)
	out = be.AppendUint16(out, 1)
	out = be.AppendUint32(out, t.negTTL)
	rdlen := (1 + 2 + len(name)) + (1 + 10 + len(name)) + 20
	out = be.AppendUint16(out, uint16(rdlen))
	out = append(out, 2, 'n', 's')
	out = append(out, name...)
	out = append(out, 10)
	out = append(out, "hostmaster"...)
	out = append(out, name...)
	out = be.AppendUint32(out, t.serial)
	out = be.AppendUint32(out, 3600)
	out = be.AppendUint32(out, 600)
	out = be.AppendUint32(out, 86400)
	return be.AppendUint32(out, t.negTTL)
}

func appendOPT(out []byte) []byte {
	out = append(out, 0)
	out = be.AppendUint16(out, 41)
	out = be.AppendUint16(out, MaxUDP)
	out = be.AppendUint32(out, 0)
	return be.AppendUint16(out, 0)
}

// Respond answers q from the table when it holds the name or owns its zone; otherwise it reports Forward and
// dst is untouched. UDP answers are cut to the client's EDNS size (512 without EDNS, at most MaxUDP) with TC set.
func (t *Table) Respond(q []byte, dst []byte, tcp bool) ([]byte, Status) {
	p, ok := parseQuery(q)
	if !ok || p.qclass != 1 || p.qtype == 41 {
		return dst[:0], Forward
	}
	qw := q[p.nameStart:p.nameEnd]
	res := t.resolve(qw)
	if res.kind == rForward {
		return dst[:0], Forward
	}
	if p.qtype == TypeAXFR || p.qtype == TypeIXFR {
		res.kind = rRefuse
	}
	flags := uint16(0x8000|0x0400|0x0080) | p.flags&0x0100
	out := append(dst[:0], q[0], q[1])
	hdr := len(out)
	out = be.AppendUint16(out, flags)
	out = append(out, 0, 1, 0, 0, 0, 0, 0, 0)
	out = append(out, q[12:p.qEnd]...)
	var an, ns int
	switch res.kind {
	case rAnswer:
		out = t.writeAnswer(out, res.g, p.qtype, &an)
		if an == 0 {
			if res.apex < 0 {
				res.apex = t.zoneApex(qw)
			}
			if res.apex >= 0 {
				out = t.writeSOA(out, res.apex)
				ns = 1
			}
		}
	case rNoData, rNXDomain:
		if res.kind == rNXDomain {
			be.PutUint16(out[hdr:], flags|3)
		}
		out = t.writeSOA(out, res.apex)
		ns = 1
	case rRefuse:
		be.PutUint16(out[hdr:], flags|5)
	}
	ar := 0
	if p.hasOPT {
		out = appendOPT(out)
		ar = 1
	}
	be.PutUint16(out[hdr+4:], uint16(an))
	be.PutUint16(out[hdr+6:], uint16(ns))
	be.PutUint16(out[hdr+8:], uint16(ar))
	limit := 65535
	if !tcp {
		limit = 512
		if p.hasOPT {
			limit = min(max(int(p.optSize), 512), MaxUDP)
		}
	}
	if len(out) > limit {
		fl := be.Uint16(out[hdr:]) | 0x0200
		out = append(dst[:0], q[0], q[1])
		out = be.AppendUint16(out, fl)
		out = append(out, 0, 1, 0, 0, 0, 0, 0, 0)
		out = append(out, q[12:p.qEnd]...)
		if p.hasOPT {
			out = appendOPT(out)
			be.PutUint16(out[hdr+8:], 1)
		}
	}
	return out, Answered
}
