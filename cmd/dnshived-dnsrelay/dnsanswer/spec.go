// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsanswer

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	maxSpecZones = 5000
	maxSpecRRs   = 2_000_000
)

var ErrSpec = errors.New("dnsanswer: invalid table spec")

// Spec is the transportable form of a table: what the daemon compiles from the store and sends to the relay.
type Spec struct {
	Zones  []Zone
	RRs    []RR
	Serial uint32
	NegTTL uint32
}

func (s *Spec) Build() (*Table, error) {
	b := NewBuilder()
	for _, z := range s.Zones {
		if err := b.AddZone(z.Name, z.Forward); err != nil {
			return nil, err
		}
	}
	for _, rr := range s.RRs {
		if err := b.Add(rr); err != nil {
			return nil, err
		}
	}
	return b.Build(s.Serial, s.NegTTL)
}

func (s *Spec) Encode() []byte {
	out := binary.LittleEndian.AppendUint32(nil, s.Serial)
	out = binary.LittleEndian.AppendUint32(out, s.NegTTL)
	out = binary.AppendUvarint(out, uint64(len(s.Zones)))
	for _, z := range s.Zones {
		f := byte(0)
		if z.Forward {
			f = 1
		}
		out = append(out, f, byte(len(z.Name)))
		out = append(out, z.Name...)
	}
	out = binary.AppendUvarint(out, uint64(len(s.RRs)))
	for _, rr := range s.RRs {
		out = append(out, byte(len(rr.Owner)))
		out = append(out, rr.Owner...)
		out = binary.LittleEndian.AppendUint16(out, rr.Type)
		out = binary.LittleEndian.AppendUint32(out, rr.TTL)
		out = binary.LittleEndian.AppendUint16(out, uint16(len(rr.RData)))
		out = append(out, rr.RData...)
	}
	return out
}

type specReader struct {
	b   []byte
	err error
}

func (r *specReader) take(n int) []byte {
	if r.err != nil || n < 0 || n > len(r.b) {
		r.err = ErrSpec
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *specReader) uvarint() uint64 {
	if r.err != nil {
		return 0
	}
	v, n := binary.Uvarint(r.b)
	if n <= 0 {
		r.err = ErrSpec
		return 0
	}
	r.b = r.b[n:]
	return v
}

func DecodeSpec(b []byte) (*Spec, error) {
	r := &specReader{b: b}
	h := r.take(8)
	if h == nil {
		return nil, ErrSpec
	}
	s := &Spec{Serial: binary.LittleEndian.Uint32(h), NegTTL: binary.LittleEndian.Uint32(h[4:])}
	nz := r.uvarint()
	if r.err != nil || nz > maxSpecZones || nz > uint64(len(r.b)/2) {
		return nil, fmt.Errorf("%w: %d zones", ErrSpec, nz)
	}
	for i := uint64(0); i < nz; i++ {
		f := r.take(2)
		if f == nil {
			return nil, ErrSpec
		}
		name := r.take(int(f[1]))
		if name == nil {
			return nil, ErrSpec
		}
		s.Zones = append(s.Zones, Zone{Name: string(name), Forward: f[0] == 1})
	}
	nr := r.uvarint()
	if r.err != nil || nr > maxSpecRRs || nr > uint64(len(r.b)/9) {
		return nil, fmt.Errorf("%w: %d records", ErrSpec, nr)
	}
	s.RRs = make([]RR, 0, nr)
	for i := uint64(0); i < nr; i++ {
		l := r.take(1)
		if l == nil {
			return nil, ErrSpec
		}
		owner := r.take(int(l[0]))
		f := r.take(8)
		if owner == nil || f == nil {
			return nil, ErrSpec
		}
		rd := r.take(int(binary.LittleEndian.Uint16(f[6:])))
		if r.err != nil {
			return nil, ErrSpec
		}
		s.RRs = append(s.RRs, RR{Owner: string(owner), Type: binary.LittleEndian.Uint16(f), TTL: binary.LittleEndian.Uint32(f[2:]), RData: append([]byte(nil), rd...)})
	}
	if len(r.b) != 0 {
		return nil, fmt.Errorf("%w: trailing bytes", ErrSpec)
	}
	return s, nil
}
