// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsstore

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

const (
	magic      = "DHDS"
	headerSize = 64
	verMajor   = 1
	verMinor   = 0

	ftLog  byte = 'L'
	ftSnap byte = 'S'
	ftMeta byte = 'M'

	recBatch  byte = 1
	recNoop   byte = 2
	recRotate byte = 3

	chainSize = 32
	recFixed  = 4 + 1 + 3 + 4 + 8 + 8 + 8
	recMin    = recFixed + chainSize

	MaxRow        = 64 << 10
	MaxBatchBytes = 32 << 20
	MaxOps        = 200000
	maxAuthor     = 255
	opMin         = 1 + 1 + 16
	batchFixed    = 1 + 1 + 8 + 8 + 16 + 4
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

var le = binary.LittleEndian

type ID [16]byte

type header struct {
	ftype    byte
	major    uint16
	minor    uint16
	storeID  ID
	firstRev uint64
}

func encodeHeader(h header) []byte {
	b := make([]byte, headerSize)
	copy(b, magic)
	b[4] = h.ftype
	le.PutUint16(b[6:], h.major)
	le.PutUint16(b[8:], h.minor)
	copy(b[12:], h.storeID[:])
	le.PutUint64(b[28:], h.firstRev)
	le.PutUint32(b[60:], crc32.Checksum(b[:60], castagnoli))
	return b
}

func decodeHeader(b []byte, name string) (header, error) {
	if len(b) < headerSize {
		return header{}, corrupt(name, 0, "header is %d bytes", len(b))
	}
	if string(b[:4]) != magic {
		return header{}, corrupt(name, 0, "bad magic")
	}
	if crc32.Checksum(b[:60], castagnoli) != le.Uint32(b[60:]) {
		return header{}, corrupt(name, 0, "header checksum mismatch")
	}
	h := header{ftype: b[4], major: le.Uint16(b[6:]), minor: le.Uint16(b[8:]), firstRev: le.Uint64(b[28:])}
	copy(h.storeID[:], b[12:28])
	if h.major != verMajor {
		return header{}, fmt.Errorf("%w: %s has major version %d", ErrVersion, name, h.major)
	}
	return h, nil
}

type OpKind uint8

const (
	OpPut OpKind = 1
	OpDel OpKind = 2
)

type Op struct {
	Kind OpKind
	Type uint8
	ID   ID
	Body []byte
}

type Batch struct {
	Origin        uint8
	Author        string
	TimeMs        int64
	ConfigBaseRev uint64
	ImportID      ID
	ImportSeq     uint32
	Ops           []Op
}

func validateBatch(b *Batch) error {
	if len(b.Ops) == 0 {
		return fmt.Errorf("%w: no operations", ErrBadBatch)
	}
	if len(b.Ops) > MaxOps {
		return fmt.Errorf("%w: %d operations", ErrTooLarge, len(b.Ops))
	}
	if len(b.Author) > maxAuthor {
		return fmt.Errorf("%w: author is %d bytes", ErrBadBatch, len(b.Author))
	}
	size := batchFixed + len(b.Author) + binary.MaxVarintLen64
	for i := range b.Ops {
		op := &b.Ops[i]
		switch op.Kind {
		case OpPut:
			if len(op.Body) > MaxRow {
				return fmt.Errorf("%w: row of %d bytes", ErrTooLarge, len(op.Body))
			}
		case OpDel:
			if len(op.Body) != 0 {
				return fmt.Errorf("%w: delete with a body", ErrBadBatch)
			}
		default:
			return fmt.Errorf("%w: operation kind %d", ErrBadBatch, op.Kind)
		}
		if op.Type == 0 {
			return fmt.Errorf("%w: row type 0", ErrBadBatch)
		}
		size += opMin + binary.MaxVarintLen64 + len(op.Body)
		if size > MaxBatchBytes {
			return fmt.Errorf("%w: batch over %d bytes", ErrTooLarge, MaxBatchBytes)
		}
	}
	return nil
}

func encodeBatch(b *Batch) ([]byte, error) {
	if err := validateBatch(b); err != nil {
		return nil, err
	}
	out := make([]byte, 0, batchFixed+len(b.Author)+len(b.Ops)*(opMin+8))
	out = append(out, b.Origin, byte(len(b.Author)))
	out = append(out, b.Author...)
	out = le.AppendUint64(out, uint64(b.TimeMs))
	out = le.AppendUint64(out, b.ConfigBaseRev)
	out = append(out, b.ImportID[:]...)
	out = le.AppendUint32(out, b.ImportSeq)
	out = binary.AppendUvarint(out, uint64(len(b.Ops)))
	for i := range b.Ops {
		op := &b.Ops[i]
		out = append(out, byte(op.Kind), op.Type)
		out = append(out, op.ID[:]...)
		if op.Kind == OpPut {
			out = binary.AppendUvarint(out, uint64(len(op.Body)))
			out = append(out, op.Body...)
		}
	}
	if len(out) > MaxBatchBytes {
		return nil, fmt.Errorf("%w: batch of %d bytes", ErrTooLarge, len(out))
	}
	return out, nil
}

type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.b) {
		r.err = io.ErrUnexpectedEOF
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) uvarint() uint64 {
	if r.err != nil {
		return 0
	}
	v, n := binary.Uvarint(r.b)
	if n <= 0 {
		r.err = io.ErrUnexpectedEOF
		return 0
	}
	r.b = r.b[n:]
	return v
}

func decodeBatch(p []byte) (Batch, error) {
	r := &reader{b: p}
	var b Batch
	head := r.take(2)
	if head == nil {
		return b, fmt.Errorf("%w: short batch", ErrBadBatch)
	}
	b.Origin = head[0]
	b.Author = string(r.take(int(head[1])))
	fixed := r.take(8 + 8 + 16 + 4)
	if fixed == nil {
		return b, fmt.Errorf("%w: short batch header", ErrBadBatch)
	}
	b.TimeMs = int64(le.Uint64(fixed))
	b.ConfigBaseRev = le.Uint64(fixed[8:])
	copy(b.ImportID[:], fixed[16:32])
	b.ImportSeq = le.Uint32(fixed[32:])
	n := r.uvarint()
	if r.err != nil || n == 0 || n > MaxOps || n > uint64(len(r.b)/opMin) {
		return b, fmt.Errorf("%w: operation count", ErrBadBatch)
	}
	b.Ops = make([]Op, 0, n)
	for i := uint64(0); i < n; i++ {
		h := r.take(2 + 16)
		if h == nil {
			return b, fmt.Errorf("%w: short operation", ErrBadBatch)
		}
		op := Op{Kind: OpKind(h[0]), Type: h[1]}
		copy(op.ID[:], h[2:])
		switch op.Kind {
		case OpPut:
			l := r.uvarint()
			if l > MaxRow {
				return b, fmt.Errorf("%w: row of %d bytes", ErrTooLarge, l)
			}
			op.Body = r.take(int(l))
		case OpDel:
		default:
			return b, fmt.Errorf("%w: operation kind %d", ErrBadBatch, op.Kind)
		}
		if r.err != nil || op.Type == 0 {
			return b, fmt.Errorf("%w: operation %d", ErrBadBatch, i)
		}
		b.Ops = append(b.Ops, op)
	}
	if len(r.b) != 0 {
		return b, fmt.Errorf("%w: %d trailing bytes", ErrBadBatch, len(r.b))
	}
	return b, nil
}

type record struct {
	typ      byte
	keyEpoch uint32
	term     uint64
	rev      uint64
	commit   uint64
	payload  []byte
	chain    [chainSize]byte
}

func encodeRecord(r *record) []byte {
	n := recMin + len(r.payload)
	b := make([]byte, 4+n)
	le.PutUint32(b, uint32(n))
	b[8] = r.typ
	le.PutUint32(b[12:], r.keyEpoch)
	le.PutUint64(b[16:], r.term)
	le.PutUint64(b[24:], r.rev)
	le.PutUint64(b[32:], r.commit)
	copy(b[40:], r.payload)
	copy(b[40+len(r.payload):], r.chain[:])
	le.PutUint32(b[4:], crc32.Checksum(b[8:], castagnoli))
	return b
}

var (
	errEnd  = errors.New("end of log")
	errTorn = errors.New("torn record")
)

func readRecord(r *bufio.Reader, remain int64) (record, int64, error) {
	if remain < 4 {
		return record{}, 0, errEnd
	}
	var lenb [4]byte
	if _, err := io.ReadFull(r, lenb[:]); err != nil {
		if err == io.EOF {
			return record{}, 0, errEnd
		}
		return record{}, 0, errTorn
	}
	n := int64(le.Uint32(lenb[:]))
	if n == 0 {
		return record{}, 0, errEnd
	}
	if n < recMin || n > MaxBatchBytes+recMin+1024 || n > remain-4 {
		return record{}, 0, errTorn
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return record{}, 0, errTorn
	}
	if crc32.Checksum(body[4:], castagnoli) != le.Uint32(body) {
		return record{}, 0, errTorn
	}
	rec := record{
		typ:      body[4],
		keyEpoch: le.Uint32(body[8:]),
		term:     le.Uint64(body[12:]),
		rev:      le.Uint64(body[20:]),
		commit:   le.Uint64(body[28:]),
		payload:  body[36 : n-chainSize],
	}
	copy(rec.chain[:], body[n-chainSize:])
	return rec, 4 + n, nil
}

type Keys interface {
	Key(epoch uint32) ([]byte, bool)
	Current() uint32
}

type StaticKeys struct {
	Cur    uint32
	Epochs map[uint32][]byte
}

func (k StaticKeys) Key(epoch uint32) ([]byte, bool) {
	v, ok := k.Epochs[epoch]
	return v, ok
}

func (k StaticKeys) Current() uint32 { return k.Cur }

func chainNext(key []byte, prev [chainSize]byte, typ byte, epoch uint32, term, rev, commit uint64, payload []byte) [chainSize]byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(prev[:])
	var h [29]byte
	h[0] = typ
	le.PutUint32(h[1:], epoch)
	le.PutUint64(h[5:], term)
	le.PutUint64(h[13:], rev)
	le.PutUint64(h[21:], commit)
	mac.Write(h[:])
	mac.Write(payload)
	var out [chainSize]byte
	mac.Sum(out[:0])
	return out
}

func genesisChain(key []byte, id ID) [chainSize]byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("dnshived-dnsstore-genesis"))
	mac.Write(id[:])
	var out [chainSize]byte
	mac.Sum(out[:0])
	return out
}
