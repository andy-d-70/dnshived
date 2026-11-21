// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsstore

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash"
	"maps"
)

const numShards = 256

type rowKey struct {
	typ uint8
	id  ID
}

type rowVal struct {
	rev  uint64
	body []byte
}

type shard struct {
	rows  map[rowKey]rowVal
	tombs map[rowKey]uint64
}

// View is an immutable state of the store at one revision; readers never lock.
type View struct {
	shards   [numShards]*shard
	hashes   [numShards][chainSize]byte
	rev      uint64
	term     uint64
	chain    [chainSize]byte
	keyEpoch uint32
	rows     int
	tombs    int
}

func (v *View) Rev() uint64        { return v.rev }
func (v *View) Term() uint64       { return v.term }
func (v *View) Chain() [32]byte    { return v.chain }
func (v *View) KeyEpoch() uint32   { return v.keyEpoch }
func (v *View) Len() int           { return v.rows }
func (v *View) Tombstones() int    { return v.tombs }
func (v *View) Manifest() [32]byte { return manifestOf(&v.hashes) }

func (v *View) PartitionHashes() [numShards][32]byte { return v.hashes }

// CountOf counts the rows of one type without touching their bodies.
func (v *View) CountOf(typ uint8) int {
	n := 0
	for _, sh := range v.shards {
		if sh == nil {
			continue
		}
		for k := range sh.rows {
			if k.typ == typ {
				n++
			}
		}
	}
	return n
}

// Get returns the stored body; the caller must not modify it.
func (v *View) Get(typ uint8, id ID) ([]byte, uint64, bool) {
	sh := v.shards[id[0]]
	if sh == nil {
		return nil, 0, false
	}
	r, ok := sh.rows[rowKey{typ, id}]
	return r.body, r.rev, ok
}

func (v *View) Tombstone(typ uint8, id ID) (uint64, bool) {
	sh := v.shards[id[0]]
	if sh == nil {
		return 0, false
	}
	rev, ok := sh.tombs[rowKey{typ, id}]
	return rev, ok
}

// Range visits the rows of one type in no particular order until fn returns false.
func (v *View) Range(typ uint8, fn func(id ID, rev uint64, body []byte) bool) {
	for _, sh := range v.shards {
		if sh == nil {
			continue
		}
		for k, r := range sh.rows {
			if k.typ == typ && !fn(k.id, r.rev, r.body) {
				return
			}
		}
	}
}

func manifestOf(h *[numShards][chainSize]byte) [32]byte {
	s := sha256.New()
	for i := range h {
		s.Write(h[i][:])
	}
	var out [32]byte
	s.Sum(out[:0])
	return out
}

type rowHasher struct {
	mac hash.Hash
	buf [1 + 16 + 8]byte
}

func partitionKey(key []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("dnshived-dnsstore-partition"))
	return m.Sum(nil)
}

func newRowHasher(key []byte) *rowHasher {
	return &rowHasher{mac: hmac.New(sha256.New, partitionKey(key))}
}

func (h *rowHasher) sum(k rowKey, rev uint64, body []byte) [chainSize]byte {
	h.mac.Reset()
	h.buf[0] = k.typ
	copy(h.buf[1:], k.id[:])
	le.PutUint64(h.buf[17:], rev)
	h.mac.Write(h.buf[:])
	h.mac.Write(body)
	var out [chainSize]byte
	h.mac.Sum(out[:0])
	return out
}

func xorInto(dst *[chainSize]byte, src [chainSize]byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

func cloneShard(s *shard) *shard {
	n := &shard{rows: map[rowKey]rowVal{}, tombs: map[rowKey]uint64{}}
	if s != nil {
		n.rows = maps.Clone(s.rows)
		n.tombs = maps.Clone(s.tombs)
	}
	return n
}

func genesisView(chain [chainSize]byte, epoch uint32) *View {
	return &View{chain: chain, keyEpoch: epoch}
}

// withOps returns the view after applying ops at rev; v is not modified.
func (v *View) withOps(ops []Op, rev, term uint64, chain [chainSize]byte, h *rowHasher) *View {
	nv := *v
	nv.rev, nv.term, nv.chain = rev, term, chain
	var cloned [numShards]bool
	for i := range ops {
		op := &ops[i]
		si := op.ID[0]
		if !cloned[si] {
			nv.shards[si] = cloneShard(v.shards[si])
			cloned[si] = true
		}
		sh := nv.shards[si]
		k := rowKey{op.Type, op.ID}
		old, had := sh.rows[k]
		if had {
			xorInto(&nv.hashes[si], h.sum(k, old.rev, old.body))
		}
		switch op.Kind {
		case OpPut:
			body := append([]byte(nil), op.Body...)
			sh.rows[k] = rowVal{rev: rev, body: body}
			xorInto(&nv.hashes[si], h.sum(k, rev, body))
			if !had {
				nv.rows++
			}
			if _, ok := sh.tombs[k]; ok {
				delete(sh.tombs, k)
				nv.tombs--
			}
		case OpDel:
			if had {
				delete(sh.rows, k)
				nv.rows--
			}
			if _, ok := sh.tombs[k]; !ok {
				nv.tombs++
			}
			sh.tombs[k] = rev
		}
	}
	return &nv
}

// withRotation returns the view after a key rotation: every partition hash is recomputed under the new key.
func (v *View) withRotation(rev, term uint64, chain [chainSize]byte, epoch uint32, h *rowHasher) *View {
	nv := *v
	nv.rev, nv.term, nv.chain, nv.keyEpoch = rev, term, chain, epoch
	nv.hashes = v.recompute(h)
	return &nv
}

func (v *View) recompute(h *rowHasher) [numShards][chainSize]byte {
	var out [numShards][chainSize]byte
	for si, sh := range v.shards {
		if sh == nil {
			continue
		}
		for k, r := range sh.rows {
			xorInto(&out[si], h.sum(k, r.rev, r.body))
		}
	}
	return out
}

func (v *View) verify(h *rowHasher) error {
	rows, tombs := 0, 0
	for si, sh := range v.shards {
		if sh == nil {
			continue
		}
		rows += len(sh.rows)
		tombs += len(sh.tombs)
		for k := range sh.rows {
			if int(k.id[0]) != si {
				return fmt.Errorf("%w: row in the wrong partition %d", ErrCorrupt, si)
			}
		}
	}
	if rows != v.rows || tombs != v.tombs {
		return fmt.Errorf("%w: counts rows=%d/%d tombstones=%d/%d", ErrCorrupt, rows, v.rows, tombs, v.tombs)
	}
	if got := v.recompute(h); got != v.hashes {
		return fmt.Errorf("%w: partition hashes differ from the rows", ErrCorrupt)
	}
	return nil
}

func (v *View) withoutTombstones(upTo uint64) *View {
	nv := *v
	for si, sh := range v.shards {
		if sh == nil {
			continue
		}
		drop := false
		for _, rev := range sh.tombs {
			if rev <= upTo {
				drop = true
				break
			}
		}
		if !drop {
			continue
		}
		n := &shard{rows: sh.rows, tombs: map[rowKey]uint64{}}
		for k, rev := range sh.tombs {
			if rev > upTo {
				n.tombs[k] = rev
			}
		}
		nv.tombs -= len(sh.tombs) - len(n.tombs)
		nv.shards[si] = n
	}
	return &nv
}
