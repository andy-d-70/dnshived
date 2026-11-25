// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package cfgjournal records every change of a configuration document item by item, with the old and the new value,
// in a checksummed, replicated log, and applies the changes to the document files. The old value makes every change
// reversible and is compared before a change is applied, so a change based on an outdated view is refused instead of
// replacing someone else's work.
package cfgjournal

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	maxDoc     = 64
	maxPath    = 4096
	maxAuthor  = 255
	maxValue   = 24 << 20
	maxEntries = 100000
)

var ErrEntry = errors.New("cfgjournal: invalid entry")

// Entry is one changed item. Old and New hold JSON; nil means the item is absent (added when Old is nil, removed when
// New is nil). Base is the journal revision the change was computed from.
type Entry struct {
	Doc    string
	Path   string
	Old    []byte
	New    []byte
	Base   uint64
	Author string
	TimeMs int64
	Origin uint8
	Seq    uint32
}

func (e *Entry) validate() error {
	switch {
	case e.Doc == "" || len(e.Doc) > maxDoc:
		return fmt.Errorf("%w: document name", ErrEntry)
	case e.Path == "" || len(e.Path) > maxPath:
		return fmt.Errorf("%w: path", ErrEntry)
	case len(e.Author) > maxAuthor:
		return fmt.Errorf("%w: author", ErrEntry)
	case len(e.Old) > maxValue || len(e.New) > maxValue:
		return fmt.Errorf("%w: value too large", ErrEntry)
	case e.Old == nil && e.New == nil:
		return fmt.Errorf("%w: %s changes nothing", ErrEntry, e.Path)
	case e.TimeMs < 0:
		return fmt.Errorf("%w: time", ErrEntry)
	}
	return nil
}

func appendField(b []byte, tag byte, v []byte) []byte {
	b = append(b, tag)
	b = binary.AppendUvarint(b, uint64(len(v)))
	return append(b, v...)
}

func appendNum(b []byte, tag byte, v uint64) []byte {
	var tmp [binary.MaxVarintLen64]byte
	return appendField(b, tag, tmp[:binary.PutUvarint(tmp[:], v)])
}

// encode writes tagged fields; a value field is present exactly when the value is, even when it is empty.
func (e *Entry) encode() []byte {
	b := make([]byte, 0, 48+len(e.Doc)+len(e.Path)+len(e.Author)+len(e.Old)+len(e.New))
	b = appendField(b, 1, []byte(e.Doc))
	b = appendField(b, 2, []byte(e.Path))
	if e.Old != nil {
		b = appendField(b, 3, e.Old)
	}
	if e.New != nil {
		b = appendField(b, 4, e.New)
	}
	b = appendNum(b, 5, e.Base)
	if e.Author != "" {
		b = appendField(b, 6, []byte(e.Author))
	}
	b = appendNum(b, 7, uint64(e.TimeMs))
	b = appendNum(b, 8, uint64(e.Origin))
	return appendNum(b, 9, uint64(e.Seq))
}

func decodeEntry(b []byte) (Entry, error) {
	var e Entry
	for len(b) > 0 {
		tag := b[0]
		l, n := binary.Uvarint(b[1:])
		if n <= 0 || l > uint64(len(b)-1-n) {
			return e, fmt.Errorf("%w: truncated field", ErrEntry)
		}
		v := b[1+n : 1+n+int(l)]
		b = b[1+n+int(l):]
		num := func(limit uint64) (uint64, error) {
			x, k := binary.Uvarint(v)
			if k <= 0 || k != len(v) || x > limit {
				return 0, fmt.Errorf("%w: number in field %d", ErrEntry, tag)
			}
			return x, nil
		}
		var err error
		var x uint64
		switch tag {
		case 1:
			e.Doc = string(v)
		case 2:
			e.Path = string(v)
		case 3:
			e.Old = append([]byte{}, v...)
		case 4:
			e.New = append([]byte{}, v...)
		case 5:
			e.Base, err = num(^uint64(0))
		case 6:
			e.Author = string(v)
		case 7:
			x, err = num(1<<63 - 1)
			e.TimeMs = int64(x)
		case 8:
			x, err = num(255)
			e.Origin = uint8(x)
		case 9:
			x, err = num(1<<32 - 1)
			e.Seq = uint32(x)
		}
		if err != nil {
			return e, err
		}
	}
	return e, e.validate()
}
