// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsanswer

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"slices"
	"sort"
	"strings"
)

const (
	flagZone uint8 = 1
	flagFwd  uint8 = 2
	flagDead uint8 = 4
	flagENT  uint8 = 8
)

type RR struct {
	Owner string
	Type  uint16
	TTL   uint32
	RData []byte
}

type Zone struct {
	Name    string
	Forward bool
}

// group is one owner name with its resource records; the table holds no pointers, so the GC does not scan it.
type group struct {
	nameOff uint32
	firstRR uint32
	nRR     uint16
	nameLen uint8
	flags   uint8
	hash    uint32
}

type rrEnt struct {
	typ   uint16
	rdLen uint16
	ttl   uint32
	rdOff uint32
}

type Table struct {
	arena   []byte
	groups  []group
	rrs     []rrEnt
	buckets []uint32
	mask    uint32
	serial  uint32
	negTTL  uint32
	digest  [32]byte
	over    *Table
}

func (t *Table) Digest() [32]byte { return t.digest }
func (t *Table) Names() int       { return len(t.groups) }
func (t *Table) Records() int     { return len(t.rrs) }

type Builder struct {
	rrs     []RR
	zones   map[string]bool
	dead    map[string]bool
	overlay bool
}

func NewBuilder() *Builder { return &Builder{zones: map[string]bool{}} }

// NewOverlayBuilder builds the small table that sits in front of a base table (see WithOverlay): the zones only tell it
// which names are empty non-terminals, they are not part of the result; an owner added with AddDead hides the base's
// records for that name.
func NewOverlayBuilder() *Builder { return &Builder{zones: map[string]bool{}, overlay: true} }

func (b *Builder) AddDead(owner string) error {
	c, err := CanonicalName(owner)
	if err != nil || c != owner {
		return fmt.Errorf("%w: owner %q is not canonical", ErrName, owner)
	}
	if b.dead == nil {
		b.dead = map[string]bool{}
	}
	b.dead[c] = true
	return nil
}

func (b *Builder) AddZone(name string, forward bool) error {
	c, err := CanonicalName(name)
	if err != nil || c != name || strings.HasPrefix(c, "*") {
		return fmt.Errorf("%w: zone %q", ErrName, name)
	}
	if old, ok := b.zones[c]; ok && old != forward {
		return fmt.Errorf("dnsanswer: zone %q is both served and forwarded", name)
	}
	b.zones[c] = forward
	return nil
}

func (b *Builder) Add(rr RR) error {
	c, err := CanonicalName(rr.Owner)
	if err != nil || c != rr.Owner {
		return fmt.Errorf("%w: owner %q is not canonical", ErrName, rr.Owner)
	}
	if rr.Type == 0 || rr.Type == 41 || len(rr.RData) > 65535 {
		return fmt.Errorf("dnsanswer: bad record %q type %d", rr.Owner, rr.Type)
	}
	b.rrs = append(b.rrs, RR{Owner: rr.Owner, Type: rr.Type, TTL: rr.TTL, RData: append([]byte(nil), rr.RData...)})
	return nil
}

type pending struct {
	name  string
	flags uint8
	rrs   []RR
}

func hashFold(w []byte) uint32 {
	h := uint32(2166136261)
	for _, c := range w {
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		h = (h ^ uint32(c)) * 16777619
	}
	return h
}

func eqFold(lower, w []byte) bool {
	if len(lower) != len(w) {
		return false
	}
	for i, c := range w {
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		if lower[i] != c {
			return false
		}
	}
	return true
}

func (b *Builder) enclosingZone(name string) (string, bool, bool) {
	for n := name; ; {
		if fwd, ok := b.zones[n]; ok {
			return n, fwd, true
		}
		i := strings.IndexByte(n, '.')
		if i < 0 {
			return "", false, false
		}
		n = n[i+1:]
	}
}

// Build compiles the table; serial and negTTL feed the synthesised SOA of negative answers.
func (b *Builder) Build(serial, negTTL uint32) (*Table, error) {
	owners := map[string]*pending{}
	get := func(n string) *pending {
		p := owners[n]
		if p == nil {
			p = &pending{name: n}
			owners[n] = p
		}
		return p
	}
	if !b.overlay {
		for z, fwd := range b.zones {
			p := get(z)
			p.flags |= flagZone
			if fwd {
				p.flags |= flagFwd
			}
		}
	}
	for n := range b.dead {
		get(n).flags |= flagDead
	}
	for _, rr := range b.rrs {
		p := get(rr.Owner)
		p.rrs = append(p.rrs, rr)
		zn, fwd, ok := b.enclosingZone(rr.Owner)
		if !ok || fwd {
			continue
		}
		for n := rr.Owner; n != zn; {
			i := strings.IndexByte(n, '.')
			if i < 0 {
				break
			}
			n = n[i+1:]
			get(n)
		}
	}
	names := make([]string, 0, len(owners))
	for n, p := range owners {
		if b.overlay && p.flags == 0 && len(p.rrs) == 0 {
			p.flags = flagENT
		}
		names = append(names, n)
	}
	sort.Strings(names)
	t := &Table{serial: serial, negTTL: negTTL}
	var h hash.Hash
	if !b.overlay {
		h = sha256.New()
		var u [8]byte
		binary.LittleEndian.PutUint32(u[:], serial)
		binary.LittleEndian.PutUint32(u[4:], negTTL)
		h.Write(u[:])
	}
	for _, n := range names {
		p := owners[n]
		wire, err := ToWire(n)
		if err != nil {
			return nil, err
		}
		if len(p.rrs) > 1 {
			slices.SortFunc(p.rrs, func(a, b RR) int {
				if a.Type != b.Type {
					return int(a.Type) - int(b.Type)
				}
				return bytes.Compare(a.RData, b.RData)
			})
		}
		uniq := p.rrs[:0]
		for _, rr := range p.rrs {
			if k := len(uniq); k > 0 && uniq[k-1].Type == rr.Type && bytes.Equal(uniq[k-1].RData, rr.RData) {
				continue
			}
			uniq = append(uniq, rr)
		}
		if len(uniq) > 65535 {
			return nil, fmt.Errorf("dnsanswer: %d records at %q", len(uniq), n)
		}
		g := group{nameOff: uint32(len(t.arena)), firstRR: uint32(len(t.rrs)), nRR: uint16(len(uniq)), nameLen: uint8(len(wire)), flags: p.flags, hash: hashFold(wire)}
		t.arena = append(t.arena, wire...)
		if h != nil {
			h.Write([]byte{byte(len(wire)), p.flags})
			h.Write(wire)
		}
		for _, rr := range uniq {
			t.rrs = append(t.rrs, rrEnt{typ: rr.Type, rdLen: uint16(len(rr.RData)), ttl: rr.TTL, rdOff: uint32(len(t.arena))})
			t.arena = append(t.arena, rr.RData...)
			if h != nil {
				var e [8]byte
				binary.LittleEndian.PutUint16(e[:], rr.Type)
				binary.LittleEndian.PutUint32(e[2:], rr.TTL)
				binary.LittleEndian.PutUint16(e[6:], uint16(len(rr.RData)))
				h.Write(e[:])
				h.Write(rr.RData)
			}
		}
		t.groups = append(t.groups, g)
		if len(t.arena) > 1<<31 || len(t.rrs) > 1<<30 {
			return nil, errors.New("dnsanswer: table too large")
		}
	}
	size := uint32(8)
	for int(size) < 2*len(t.groups) {
		size <<= 1
	}
	t.buckets = make([]uint32, size)
	t.mask = size - 1
	for i := range t.groups {
		for j := t.groups[i].hash & t.mask; ; j = (j + 1) & t.mask {
			if t.buckets[j] == 0 {
				t.buckets[j] = uint32(i) + 1
				break
			}
		}
	}
	if h != nil {
		h.Sum(t.digest[:0])
	}
	return t, nil
}

func (t *Table) name(g *group) []byte { return t.arena[g.nameOff : g.nameOff+uint32(g.nameLen)] }

func (t *Table) index(w []byte) int {
	if len(t.buckets) == 0 {
		return -1
	}
	hv := hashFold(w)
	for j := hv & t.mask; ; j = (j + 1) & t.mask {
		e := t.buckets[j]
		if e == 0 {
			return -1
		}
		g := &t.groups[e-1]
		if g.hash == hv && eqFold(t.name(g), w) {
			return int(e - 1)
		}
	}
}

// find looks a name up, in the overlay first when this table is a view with one.
func (t *Table) find(w []byte) gref {
	if t.over != nil {
		return t.findOver(w)
	}
	if len(t.buckets) == 0 {
		return gref{}
	}
	hv := hashFold(w)
	for j := hv & t.mask; ; j = (j + 1) & t.mask {
		e := t.buckets[j]
		if e == 0 {
			return gref{}
		}
		if g := &t.groups[e-1]; g.hash == hv && eqFold(t.name(g), w) {
			return gref{t, int32(e - 1)}
		}
	}
}

func (t *Table) findOver(w []byte) gref {
	if i := t.over.index(w); i >= 0 {
		switch f := t.over.groups[i].flags; {
		case f&flagDead != 0:
			return gref{}
		case f&flagENT != 0:
			if j := t.index(w); j >= 0 {
				return gref{t, int32(j)}
			}
		}
		return gref{t.over, int32(i)}
	}
	if j := t.index(w); j >= 0 {
		return gref{t, int32(j)}
	}
	return gref{}
}
