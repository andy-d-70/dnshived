// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsanswer

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

type rrOut struct {
	owner string
	typ   uint16
	ttl   uint32
	data  string
}

type respOut struct {
	id     uint16
	flags  uint16
	rcode  int
	qname  string
	an, ns []rrOut
	ar     int
}

func mkQuery(name string, qtype uint16, opt bool, size uint16) []byte {
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	if opt {
		q[11] = 1
	}
	if name == "" {
		q = append(q, 0)
	} else {
		for _, l := range strings.Split(name, ".") {
			q = append(q, byte(len(l)))
			q = append(q, l...)
		}
		q = append(q, 0)
	}
	q = be.AppendUint16(q, qtype)
	q = be.AppendUint16(q, 1)
	if opt {
		q = append(q, 0)
		q = be.AppendUint16(q, 41)
		q = be.AppendUint16(q, size)
		q = be.AppendUint32(q, 0)
		q = be.AppendUint16(q, 0)
	}
	return q
}

func readName(t testing.TB, msg []byte, off int) (string, int) {
	t.Helper()
	var parts []string
	next := -1
	for hops := 0; hops < 64; hops++ {
		if off >= len(msg) {
			t.Fatalf("name runs past the message")
		}
		b := int(msg[off])
		switch {
		case b == 0:
			if next < 0 {
				next = off + 1
			}
			return strings.Join(parts, "."), next
		case b&0xC0 == 0xC0:
			if next < 0 {
				next = off + 2
			}
			off = int(be.Uint16(msg[off:]) & 0x3FFF)
		default:
			parts = append(parts, strings.ToLower(string(msg[off+1:off+1+b])))
			off += 1 + b
		}
	}
	t.Fatal("name pointer loop")
	return "", 0
}

func rdataText(t testing.TB, msg []byte, typ uint16, off, n int) string {
	t.Helper()
	rd := msg[off : off+n]
	switch typ {
	case TypeA, TypeAAAA:
		a, _ := netip.AddrFromSlice(rd)
		return a.String()
	case TypeCNAME, TypePTR, TypeNS:
		s, _ := readName(t, msg, off)
		return s
	case TypeMX:
		s, _ := readName(t, msg, off+2)
		return fmt.Sprintf("%d %s", be.Uint16(rd), s)
	case TypeSRV:
		s, _ := readName(t, msg, off+6)
		return fmt.Sprintf("%d %d %d %s", be.Uint16(rd), be.Uint16(rd[2:]), be.Uint16(rd[4:]), s)
	case TypeTXT:
		var parts []string
		for i := 0; i < len(rd); {
			l := int(rd[i])
			parts = append(parts, string(rd[i+1:i+1+l]))
			i += 1 + l
		}
		return strings.Join(parts, "|")
	case TypeSOA:
		m, o := readName(t, msg, off)
		r, o := readName(t, msg, o)
		return fmt.Sprintf("%s %s %d %d %d %d %d", m, r, be.Uint32(msg[o:]), be.Uint32(msg[o+4:]), be.Uint32(msg[o+8:]), be.Uint32(msg[o+12:]), be.Uint32(msg[o+16:]))
	}
	return fmt.Sprintf("%x", rd)
}

func parseResp(t testing.TB, b []byte) respOut {
	t.Helper()
	if len(b) < 12 {
		t.Fatalf("response of %d bytes", len(b))
	}
	r := respOut{id: be.Uint16(b), flags: be.Uint16(b[2:])}
	r.rcode = int(r.flags & 0xF)
	if be.Uint16(b[4:]) != 1 {
		t.Fatalf("qdcount %d", be.Uint16(b[4:]))
	}
	an, ns, ar := int(be.Uint16(b[6:])), int(be.Uint16(b[8:])), int(be.Uint16(b[10:]))
	var off int
	r.qname, off = readName(t, b, 12)
	off += 4
	read := func(n int) []rrOut {
		var out []rrOut
		for i := 0; i < n; i++ {
			var o rrOut
			o.owner, off = readName(t, b, off)
			o.typ = be.Uint16(b[off:])
			o.ttl = be.Uint32(b[off+4:])
			rdl := int(be.Uint16(b[off+8:]))
			off += 10
			o.data = rdataText(t, b, o.typ, off, rdl)
			off += rdl
			out = append(out, o)
		}
		return out
	}
	r.an, r.ns = read(an), read(ns)
	for i := 0; i < ar; i++ {
		_, off = readName(t, b, off)
		off += 8
		off += 2 + int(be.Uint16(b[off:]))
		r.ar++
	}
	if off != len(b) {
		t.Fatalf("%d trailing bytes in the response", len(b)-off)
	}
	return r
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func rr(owner string, typ uint16, ttl uint32, rd []byte) RR {
	return RR{Owner: owner, Type: typ, TTL: ttl, RData: rd}
}

func rrA(owner, ip string) RR { return rr(owner, TypeA, 300, must(RDataA(ip))) }

func rrCNAME(owner, target string) RR { return rr(owner, TypeCNAME, 300, must(ToWire(target))) }

func table(t testing.TB, zones []Zone, rrs ...RR) *Table {
	t.Helper()
	b := NewBuilder()
	for _, z := range zones {
		if err := b.AddZone(z.Name, z.Forward); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range rrs {
		if err := b.Add(r); err != nil {
			t.Fatal(err)
		}
	}
	tb, err := b.Build(42, 60)
	if err != nil {
		t.Fatal(err)
	}
	return tb
}

func ask(t testing.TB, tb *Table, name string, qtype uint16) (respOut, Status) {
	t.Helper()
	out, st := tb.Respond(mkQuery(name, qtype, false, 0), make([]byte, 0, 4096), false)
	if st == Forward {
		return respOut{}, st
	}
	return parseResp(t, out), st
}
