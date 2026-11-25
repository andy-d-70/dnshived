// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package cfgjournal

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"dnshived/internal/dnsstore"
)

// TypePart is the store row type of one part of an entry. An entry larger than one row is split into parts that are
// always committed in the same batch.
const TypePart uint8 = 1

const partData = dnsstore.MaxRow - 64

var ErrJournal = errors.New("cfgjournal: journal")

// Meta describes one change set; it is copied into every entry.
type Meta struct {
	Author string
	Origin uint8
	TimeMs int64
}

// Record is an entry with the journal revision of the change set it belongs to.
type Record struct {
	Rev uint64
	Entry
}

// Commit writes one batch and returns once it is durable (and, when replicated, committed); dnsstore.Store.Commit
// and the replication driver's Propose both fit.
type Commit func(dnsstore.Batch) (uint64, error)

type Journal struct {
	commit Commit
}

func New(commit Commit) *Journal { return &Journal{commit: commit} }

// Append records one change set as a single batch: all of its entries become durable together or not at all. Each
// item may appear once per change set, so a replay never has to order two changes of the same item.
func (j *Journal) Append(m Meta, entries []Entry) (uint64, error) {
	if len(entries) == 0 || len(entries) > maxEntries {
		return 0, fmt.Errorf("%w: %d entries", ErrEntry, len(entries))
	}
	seen := make(map[[2]string]bool, len(entries))
	var ops []dnsstore.Op
	for i := range entries {
		e := entries[i]
		e.Author, e.Origin, e.TimeMs, e.Seq = m.Author, m.Origin, m.TimeMs, uint32(i)
		if err := e.validate(); err != nil {
			return 0, err
		}
		k := [2]string{e.Doc, e.Path}
		if seen[k] {
			return 0, fmt.Errorf("%w: %s %s appears twice in one change set", ErrEntry, e.Doc, e.Path)
		}
		seen[k] = true
		var key [16]byte
		if _, err := rand.Read(key[:]); err != nil {
			return 0, fmt.Errorf("%w: entry key: %v", ErrJournal, err)
		}
		ops = appendParts(ops, key, e.encode())
	}
	rev, err := j.commit(dnsstore.Batch{Origin: m.Origin, Author: m.Author, TimeMs: m.TimeMs, Ops: ops})
	if err != nil {
		return 0, fmt.Errorf("%w: append: %w", ErrJournal, err)
	}
	return rev, nil
}

func partID(key [16]byte, idx uint64) dnsstore.ID {
	var b [16 + binary.MaxVarintLen64]byte
	copy(b[:], key[:])
	n := binary.PutUvarint(b[16:], idx)
	sum := sha256.Sum256(append([]byte("cfgjournal-part:"), b[:16+n]...))
	return dnsstore.ID(sum[:len(dnsstore.ID{})])
}

func appendParts(ops []dnsstore.Op, key [16]byte, body []byte) []dnsstore.Op {
	count := uint64(max(1, (len(body)+partData-1)/partData))
	for i := uint64(0); i < count; i++ {
		chunk := body[min(len(body), int(i)*partData):min(len(body), int(i+1)*partData)]
		b := make([]byte, 0, 16+2*binary.MaxVarintLen64+len(chunk))
		b = append(b, key[:]...)
		b = binary.AppendUvarint(b, i)
		b = binary.AppendUvarint(b, count)
		b = append(b, chunk...)
		ops = append(ops, dnsstore.Op{Kind: dnsstore.OpPut, Type: TypePart, ID: partID(key, i), Body: b})
	}
	return ops
}

type assembly struct {
	rev   uint64
	count uint64
	parts map[uint64][]byte
}

// Since returns the entries of every change set after rev, in journal order (revision, then position in the change
// set). A missing, duplicated or unreadable part is an error, never skipped.
func Since(v *dnsstore.View, rev uint64) ([]Record, error) {
	groups := map[[16]byte]*assembly{}
	var bad error
	v.Range(TypePart, func(id dnsstore.ID, r uint64, body []byte) bool {
		if r <= rev {
			return true
		}
		var key [16]byte
		if len(body) < 16 {
			bad = fmt.Errorf("%w: part %x too short", ErrJournal, id[:4])
			return false
		}
		copy(key[:], body)
		idx, n := binary.Uvarint(body[16:])
		count, m := binary.Uvarint(body[16+max(n, 0):])
		if n <= 0 || m <= 0 || count == 0 || idx >= count || partID(key, idx) != id {
			bad = fmt.Errorf("%w: part %x has a bad header", ErrJournal, id[:4])
			return false
		}
		a := groups[key]
		if a == nil {
			a = &assembly{rev: r, count: count, parts: map[uint64][]byte{}}
			groups[key] = a
		}
		if a.rev != r || a.count != count {
			bad = fmt.Errorf("%w: parts of one entry disagree", ErrJournal)
			return false
		}
		a.parts[idx] = body[16+n+m:]
		return true
	})
	if bad != nil {
		return nil, bad
	}
	out := make([]Record, 0, len(groups))
	for key, a := range groups {
		if uint64(len(a.parts)) != a.count {
			return nil, fmt.Errorf("%w: entry %x has %d of %d parts", ErrJournal, key[:4], len(a.parts), a.count)
		}
		var body []byte
		for i := uint64(0); i < a.count; i++ {
			body = append(body, a.parts[i]...)
		}
		e, err := decodeEntry(body)
		if err != nil {
			return nil, fmt.Errorf("%w: entry %x at revision %d: %w", ErrJournal, key[:4], a.rev, err)
		}
		out = append(out, Record{Rev: a.rev, Entry: e})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Rev != out[j].Rev {
			return out[i].Rev < out[j].Rev
		}
		return out[i].Seq < out[j].Seq
	})
	return out, nil
}
