// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsanswer

import (
	"fmt"
	"sync"
	"sync/atomic"
)

// Change replaces all records of one owner (RRs) or removes the owner (Delete).
type Change struct {
	Owner  string
	RRs    []RR
	Delete bool
}

type delta struct {
	rrs  []RR
	dead bool
	seq  uint64
}

// Live serves a base table plus the changes made since it was built, so a change costs the size of the changes and not
// a rebuild of the base. One writer applies changes and publishes a new view each time; readers load the current view
// without locking. When enough changes pile up, the caller builds a new base and hands it to Rebase.
//
// An empty non-terminal (a name that exists only because a name below it does) that loses its last name below it keeps
// answering "no data" instead of "no such name" until the next Rebase; every other answer is exact.
type Live struct {
	mu    sync.Mutex
	base  *Table
	zones []Zone
	set   map[string]delta
	seq   uint64
	last  uint32
	limit int
	cur   atomic.Pointer[Table]
}

// NewLive starts with base and no changes. zones must be the zones base was built with; limit is the number of changed
// names after which Full reports true.
func NewLive(base *Table, zones []Zone, limit int) *Live {
	v := &Live{base: base, zones: zones, set: map[string]delta{}, limit: limit, last: base.serial}
	v.cur.Store(base)
	return v
}

// Table returns the current view; it answers like any table and stays valid after later changes.
func (v *Live) Table() *Table { return v.cur.Load() }

func (v *Live) Len() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.set)
}

func (v *Live) Full() bool { return v.limit > 0 && v.Len() > v.limit }

// Apply makes the changes visible at once and returns the sequence number they carry; serial is the zone serial the
// views answer with. On an error nothing is applied.
func (v *Live) Apply(serial uint32, changes []Change) (uint64, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	for i := range changes {
		c := &changes[i]
		if n, err := CanonicalName(c.Owner); err != nil || n != c.Owner {
			return 0, fmt.Errorf("%w: owner %q is not canonical", ErrName, c.Owner)
		}
		for _, rr := range c.RRs {
			if rr.Owner != c.Owner {
				return 0, fmt.Errorf("dnsanswer: record of %q listed under %q", rr.Owner, c.Owner)
			}
		}
	}
	prev := make(map[string]delta, len(changes))
	had := make(map[string]bool, len(changes))
	v.seq++
	for i := range changes {
		c := &changes[i]
		if _, seen := prev[c.Owner]; !seen {
			prev[c.Owner], had[c.Owner] = v.set[c.Owner]
		}
		d := delta{dead: c.Delete || len(c.RRs) == 0, seq: v.seq}
		if !d.dead {
			d.rrs = append([]RR(nil), c.RRs...)
		}
		v.set[c.Owner] = d
	}
	lastSerial := v.last
	v.last = max(v.last, serial)
	if err := v.publish(); err != nil {
		for o, d := range prev {
			if had[o] {
				v.set[o] = d
			} else {
				delete(v.set, o)
			}
		}
		v.seq--
		v.last = lastSerial
		return 0, err
	}
	return v.seq, nil
}

// Rebase swaps in a new base that already contains every change up to and including upto (a value Apply returned);
// later changes stay on top of it.
func (v *Live) Rebase(base *Table, zones []Zone, upto uint64) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	oldBase, oldZones, oldSet, oldLast := v.base, v.zones, v.set, v.last
	v.base, v.zones, v.set = base, zones, make(map[string]delta, len(oldSet))
	for o, d := range oldSet {
		if d.seq > upto {
			v.set[o] = d
		}
	}
	v.last = max(v.last, base.serial)
	if err := v.publish(); err != nil {
		v.base, v.zones, v.set, v.last = oldBase, oldZones, oldSet, oldLast
		return err
	}
	return nil
}

func (v *Live) publish() error {
	if len(v.set) == 0 {
		v.cur.Store(v.base)
		return nil
	}
	b := NewOverlayBuilder()
	for _, z := range v.zones {
		if err := b.AddZone(z.Name, z.Forward); err != nil {
			return err
		}
	}
	for o, d := range v.set {
		if d.dead {
			if err := b.AddDead(o); err != nil {
				return err
			}
			continue
		}
		for _, rr := range d.rrs {
			if err := b.Add(rr); err != nil {
				return err
			}
		}
	}
	over, err := b.Build(v.last, v.base.negTTL)
	if err != nil {
		return err
	}
	v.cur.Store(WithOverlay(v.base, over))
	return nil
}
