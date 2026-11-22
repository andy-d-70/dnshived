// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsfeed

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"dnsrelay/dnsanswer"
)

const (
	maxChanges   = 200_000
	maxRRsPerOwn = 65535
	chainSize    = sha256.Size
)

func chainSeed(epoch uint64, tableDigest [32]byte) [chainSize]byte {
	h := sha256.New()
	h.Write([]byte("dnshived-dnsfeed-chain-v1"))
	h.Write(le.AppendUint64(nil, epoch))
	h.Write(tableDigest[:])
	var out [chainSize]byte
	h.Sum(out[:0])
	return out
}

func chainNext(prev [chainSize]byte, body []byte) [chainSize]byte {
	h := sha256.New()
	h.Write(prev[:])
	h.Write(body)
	var out [chainSize]byte
	h.Sum(out[:0])
	return out
}

func encodeDelta(epoch, seq uint64, serial uint32, changes []dnsanswer.Change, prev [chainSize]byte) (payload []byte, chain [chainSize]byte, err error) {
	if len(changes) == 0 || len(changes) > maxChanges {
		return nil, chain, fmt.Errorf("dnsfeed: %d changes in one step", len(changes))
	}
	b := make([]byte, 0, 64+len(changes)*48)
	b = le.AppendUint64(b, epoch)
	b = le.AppendUint64(b, seq)
	b = le.AppendUint32(b, serial)
	b = binary.AppendUvarint(b, uint64(len(changes)))
	for i := range changes {
		c := &changes[i]
		if len(c.Owner) == 0 || len(c.Owner) > 255 {
			return nil, chain, fmt.Errorf("dnsfeed: owner of %d bytes", len(c.Owner))
		}
		del := c.Delete || len(c.RRs) == 0
		if del {
			b = append(b, 1, byte(len(c.Owner)))
			b = append(b, c.Owner...)
			continue
		}
		if len(c.RRs) > maxRRsPerOwn {
			return nil, chain, fmt.Errorf("dnsfeed: %d records at %q", len(c.RRs), c.Owner)
		}
		b = append(b, 0, byte(len(c.Owner)))
		b = append(b, c.Owner...)
		b = binary.AppendUvarint(b, uint64(len(c.RRs)))
		for _, rr := range c.RRs {
			if rr.Owner != c.Owner || len(rr.RData) > 65535 {
				return nil, chain, fmt.Errorf("dnsfeed: bad record at %q", c.Owner)
			}
			b = le.AppendUint16(b, rr.Type)
			b = le.AppendUint32(b, rr.TTL)
			b = le.AppendUint16(b, uint16(len(rr.RData)))
			b = append(b, rr.RData...)
		}
	}
	chain = chainNext(prev, b)
	return append(b, chain[:]...), chain, nil
}

type decodedDelta struct {
	epoch, seq uint64
	serial     uint32
	changes    []dnsanswer.Change
	chain      [chainSize]byte
	body       []byte
}

type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil || n < 0 || n > len(r.b) {
		r.err = fmt.Errorf("%w: short delta", ErrProtocol)
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) u64() uint64 {
	if b := r.take(8); b != nil {
		return le.Uint64(b)
	}
	return 0
}

func (r *reader) u32() uint32 {
	if b := r.take(4); b != nil {
		return le.Uint32(b)
	}
	return 0
}

func (r *reader) uvarint() uint64 {
	if r.err != nil {
		return 0
	}
	v, n := binary.Uvarint(r.b)
	if n <= 0 {
		r.err = fmt.Errorf("%w: bad number", ErrProtocol)
		return 0
	}
	r.b = r.b[n:]
	return v
}

func decodeDelta(p []byte) (decodedDelta, error) {
	var d decodedDelta
	if len(p) < 8+8+4+1+chainSize {
		return d, fmt.Errorf("%w: short delta", ErrProtocol)
	}
	d.body = p[:len(p)-chainSize]
	copy(d.chain[:], p[len(p)-chainSize:])
	r := &reader{b: d.body}
	d.epoch, d.seq, d.serial = r.u64(), r.u64(), r.u32()
	n := r.uvarint()
	if r.err != nil || n == 0 || n > maxChanges || n > uint64(len(r.b)/2) {
		return d, fmt.Errorf("%w: change count", ErrProtocol)
	}
	d.changes = make([]dnsanswer.Change, 0, n)
	for i := uint64(0); i < n; i++ {
		h := r.take(2)
		if h == nil {
			return d, r.err
		}
		owner := string(r.take(int(h[1])))
		c := dnsanswer.Change{Owner: owner}
		switch h[0] {
		case 1:
			c.Delete = true
		case 0:
			cnt := r.uvarint()
			if r.err != nil || cnt == 0 || cnt > maxRRsPerOwn || cnt > uint64(len(r.b)/8) {
				return d, fmt.Errorf("%w: record count", ErrProtocol)
			}
			c.RRs = make([]dnsanswer.RR, 0, cnt)
			for j := uint64(0); j < cnt; j++ {
				f := r.take(8)
				if f == nil {
					return d, r.err
				}
				rd := r.take(int(le.Uint16(f[6:])))
				if rd == nil && le.Uint16(f[6:]) != 0 {
					return d, r.err
				}
				c.RRs = append(c.RRs, dnsanswer.RR{Owner: owner, Type: le.Uint16(f), TTL: le.Uint32(f[2:]), RData: append([]byte(nil), rd...)})
			}
		default:
			return d, fmt.Errorf("%w: change flags %d", ErrProtocol, h[0])
		}
		if r.err != nil {
			return d, r.err
		}
		d.changes = append(d.changes, c)
	}
	if len(r.b) != 0 {
		return d, fmt.Errorf("%w: %d trailing bytes", ErrProtocol, len(r.b))
	}
	return d, nil
}
