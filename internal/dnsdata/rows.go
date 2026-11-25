// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package dnsdata is the DNS model stored in dnsstore: hosts that answer in several domains, records, the write gate that
// validates every change, the compilation into the table the relays answer from, and the merge with DHCP lease names.
package dnsdata

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"

	"dnshived/internal/dnsstore"
)

const (
	TypeHost   uint8 = 1
	TypeRecord uint8 = 2

	TypeRAW uint16 = 0xFFFF

	maxDomainsPerHost = 64
	maxAddrsPerHost   = 64
	maxTTL            = 1<<31 - 1
)

var ErrRow = errors.New("dnsdata: invalid row")

type Addr struct {
	IP  netip.Addr
	PTR bool
}

// Host is one device name that answers in every listed domain; the first domain owns its reverse record. OwnTTL keeps
// an own TTL of 0 apart from no own TTL (Record has the same field); a TTL above 0 is always the row's own.
type Host struct {
	Label         string
	Domains       []string
	Addrs         []Addr
	TTL           uint32
	OwnTTL        bool
	ProbeDisabled bool
	LastBy        string
	LastAt        int64
}

// Record is a non-address record, attached to a host (Host and Sub) or standing alone (Owner).
type Record struct {
	Host    dnsstore.ID
	Sub     string
	Owner   string
	Type    uint16
	TTL     uint32
	OwnTTL  bool
	Value   string
	Target  string
	Pref    uint16
	Prio    uint16
	Weight  uint16
	Port    uint16
	Order   uint16
	Flags   string
	Service string
	Regexp  string
	CAAFlag uint8
	CAATag  string
	Raw     string

	Scope         string
	ProbeDisabled bool
	LastBy        string
	LastAt        int64
}

type enc struct{ b []byte }

func (e *enc) bytes(tag byte, v []byte) {
	e.b = append(e.b, tag)
	e.b = binary.AppendUvarint(e.b, uint64(len(v)))
	e.b = append(e.b, v...)
}

func (e *enc) str(tag byte, s string) {
	if s != "" {
		e.bytes(tag, []byte(s))
	}
}

func (e *enc) num(tag byte, v uint64) {
	if v == 0 {
		return
	}
	e.uvarint(tag, v)
}

func (e *enc) uvarint(tag byte, v uint64) {
	var tmp [binary.MaxVarintLen64]byte
	e.bytes(tag, tmp[:binary.PutUvarint(tmp[:], v)])
}

func (e *enc) ttl(own bool, v uint32) {
	if own || v != 0 {
		e.uvarint(2, uint64(v))
	}
}

type field struct {
	tag byte
	val []byte
}

func fields(b []byte) ([]field, error) {
	var out []field
	for len(b) > 0 {
		tag := b[0]
		l, n := binary.Uvarint(b[1:])
		if n <= 0 || l > uint64(len(b)-1-n) {
			return nil, fmt.Errorf("%w: truncated field", ErrRow)
		}
		out = append(out, field{tag, b[1+n : 1+n+int(l)]})
		b = b[1+n+int(l):]
		if len(out) > 256 {
			return nil, fmt.Errorf("%w: too many fields", ErrRow)
		}
	}
	return out, nil
}

func num(v []byte) (uint64, error) {
	x, n := binary.Uvarint(v)
	if n != len(v) || n <= 0 {
		return 0, fmt.Errorf("%w: bad number", ErrRow)
	}
	return x, nil
}

func (h *Host) Encode() []byte {
	size := 24 + len(h.Label) + len(h.LastBy) + len(h.Addrs)*19
	for _, d := range h.Domains {
		size += len(d) + 2
	}
	e := enc{b: make([]byte, 0, size)}
	e.str(1, h.Label)
	e.ttl(h.OwnTTL, h.TTL)
	for _, d := range h.Domains {
		e.str(3, d)
	}
	for _, a := range h.Addrs {
		flag := byte(0)
		if a.PTR {
			flag = 1
		}
		e.bytes(4, append([]byte{flag}, a.IP.AsSlice()...))
	}
	if h.ProbeDisabled {
		e.num(5, 1)
	}
	e.str(6, h.LastBy)
	if h.LastAt > 0 {
		e.num(7, uint64(h.LastAt))
	}
	return e.b
}

func DecodeHost(b []byte) (Host, error) {
	var h Host
	fs, err := fields(b)
	if err != nil {
		return h, err
	}
	for _, f := range fs {
		switch f.tag {
		case 1:
			h.Label = string(f.val)
		case 2:
			v, err := num(f.val)
			if err != nil || v > maxTTL {
				return h, fmt.Errorf("%w: ttl", ErrRow)
			}
			h.TTL, h.OwnTTL = uint32(v), true
		case 3:
			h.Domains = append(h.Domains, string(f.val))
		case 4:
			ip, ok := netip.AddrFromSlice(f.val[min(1, len(f.val)):])
			if len(f.val) < 5 || !ok || f.val[0] > 1 {
				return h, fmt.Errorf("%w: address", ErrRow)
			}
			h.Addrs = append(h.Addrs, Addr{IP: ip, PTR: f.val[0] == 1})
		case 5:
			v, err := num(f.val)
			if err != nil || v > 1 {
				return h, fmt.Errorf("%w: probe flag", ErrRow)
			}
			h.ProbeDisabled = v == 1
		case 6:
			h.LastBy = string(f.val)
		case 7:
			v, err := num(f.val)
			if err != nil || v > math.MaxInt64 {
				return h, fmt.Errorf("%w: change time", ErrRow)
			}
			h.LastAt = int64(v)
		}
	}
	if len(h.Domains) > maxDomainsPerHost || len(h.Addrs) > maxAddrsPerHost {
		return h, fmt.Errorf("%w: too many domains or addresses", ErrRow)
	}
	return h, nil
}

func (r *Record) Encode() []byte {
	size := 64 + len(r.Sub) + len(r.Owner) + len(r.Value) + len(r.Target) + len(r.Flags) + len(r.Service) + len(r.Regexp) +
		len(r.CAATag) + len(r.Raw) + len(r.Scope) + len(r.LastBy)
	e := enc{b: make([]byte, 0, size)}
	e.num(1, uint64(r.Type))
	e.ttl(r.OwnTTL, r.TTL)
	if r.Host != (dnsstore.ID{}) {
		e.bytes(3, r.Host[:])
	}
	e.str(4, r.Sub)
	e.str(5, r.Owner)
	e.str(6, r.Value)
	e.str(7, r.Target)
	e.num(8, uint64(r.Pref))
	e.num(9, uint64(r.Prio))
	e.num(10, uint64(r.Weight))
	e.num(11, uint64(r.Port))
	e.str(12, r.Flags)
	e.str(13, r.Service)
	e.str(14, r.Regexp)
	e.num(15, uint64(r.CAAFlag))
	e.str(16, r.CAATag)
	e.str(17, r.Raw)
	e.num(18, uint64(r.Order))
	e.str(19, r.Scope)
	if r.ProbeDisabled {
		e.num(20, 1)
	}
	e.str(21, r.LastBy)
	if r.LastAt > 0 {
		e.num(22, uint64(r.LastAt))
	}
	return e.b
}

func DecodeRecord(b []byte) (Record, error) {
	var r Record
	fs, err := fields(b)
	if err != nil {
		return r, err
	}
	for _, f := range fs {
		switch f.tag {
		case 3:
			if len(f.val) != len(r.Host) {
				return r, fmt.Errorf("%w: host id", ErrRow)
			}
			copy(r.Host[:], f.val)
		case 4:
			r.Sub = string(f.val)
		case 5:
			r.Owner = string(f.val)
		case 6:
			r.Value = string(f.val)
		case 7:
			r.Target = string(f.val)
		case 12:
			r.Flags = string(f.val)
		case 13:
			r.Service = string(f.val)
		case 14:
			r.Regexp = string(f.val)
		case 16:
			r.CAATag = string(f.val)
		case 17:
			r.Raw = string(f.val)
		case 19:
			r.Scope = string(f.val)
		case 21:
			r.LastBy = string(f.val)
		case 1, 2, 8, 9, 10, 11, 15, 18, 20, 22:
			v, err := num(f.val)
			limit := uint64(65535)
			switch f.tag {
			case 2:
				limit = maxTTL
			case 15:
				limit = 255
			case 20:
				limit = 1
			case 22:
				limit = math.MaxInt64
			}
			if err != nil || v > limit {
				if f.tag == 2 {
					return r, fmt.Errorf("%w: ttl out of range", ErrRow)
				}
				return r, fmt.Errorf("%w: number in field %d", ErrRow, f.tag)
			}
			switch f.tag {
			case 1:
				r.Type = uint16(v)
			case 2:
				r.TTL, r.OwnTTL = uint32(v), true
			case 8:
				r.Pref = uint16(v)
			case 9:
				r.Prio = uint16(v)
			case 10:
				r.Weight = uint16(v)
			case 11:
				r.Port = uint16(v)
			case 15:
				r.CAAFlag = uint8(v)
			case 18:
				r.Order = uint16(v)
			case 20:
				r.ProbeDisabled = v == 1
			case 22:
				r.LastAt = int64(v)
			}
		}
	}
	if r.Type == 0 {
		return r, fmt.Errorf("%w: record without a type", ErrRow)
	}
	return r, nil
}
