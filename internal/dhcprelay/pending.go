// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dhcprelay

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	ShardCount = 64

	// EntryTTL is the minimum age a pending transaction reaches before it
	// becomes eligible for removal by the sweeper.
	EntryTTL = 30 * time.Second

	// MaxPending bounds total memory regardless of TTL/sweep timing -- once
	// reached, addPending refuses new transactions rather than growing without
	// limit.
	MaxPending = 65536
)

type addResult int

const (
	addOK addResult = iota
	addGlobalFull
	addVLANFull
)

// txKey identifies one in-flight client-to-server transaction.
type txKey struct {
	xid    uint32
	chaddr [6]byte
	giaddr [4]byte
}

// makeTransactionKey derives txKey from a packet and the giaddr this relay
// either stamped into it (client leg) or that the server echoed back
// (server leg).
func makeTransactionKey(p []byte, giaddr net.IP) (txKey, bool) {
	g4 := giaddr.To4()
	if g4 == nil {
		return txKey{}, false
	}
	var k txKey
	k.xid = extractXID(p)
	k.chaddr = extractCHAddr(p)
	copy(k.giaddr[:], g4)
	return k, true
}

type pendingShard struct {
	mu      sync.Mutex
	entries map[txKey]pendingEntry
}

type pendingEntry struct {
	expiresAt time.Time
	vlan      *atomic.Int64 // the owning interface's pending count, or nil
}

// pendingTable is the sharded, TTL-swept record of every DHCP request this
// relay has forwarded upstream but not yet seen (or successfully
// delivered) a reply for.
type pendingTable struct {
	shards    [ShardCount]pendingShard
	globalCnt atomic.Int64
}

func newPendingTable() *pendingTable {
	t := &pendingTable{}
	for i := range t.shards {
		t.shards[i].entries = make(map[txKey]pendingEntry)
	}
	return t
}

func (t *pendingTable) shard(k txKey) *pendingShard {
	return &t.shards[k.xid%ShardCount]
}

func (t *pendingTable) add(k txKey) bool {
	return t.addAt(k, time.Now(), nil, 0) == addOK
}

// addAt records k, counted in vlan (the interface's own pending count);
// vlanCap > 0 caps that count.
func (t *pendingTable) addAt(k txKey, now time.Time, vlan *atomic.Int64, vlanCap int) addResult {
	s := t.shard(k)
	s.mu.Lock()
	defer s.mu.Unlock()

	e, exists := s.entries[k]
	if !exists {
		if t.globalCnt.Load() >= MaxPending {
			return addGlobalFull
		}
		if vlan != nil {
			if vlanCap > 0 && vlan.Load() >= int64(vlanCap) {
				return addVLANFull
			}
			vlan.Add(1)
		}
		t.globalCnt.Add(1)
		e.vlan = vlan
	}
	e.expiresAt = now.Add(EntryTTL)
	s.entries[k] = e
	return addOK
}

func (t *pendingTable) removeLocked(s *pendingShard, k txKey, e pendingEntry) {
	delete(s.entries, k)
	t.globalCnt.Add(-1)
	if e.vlan != nil {
		e.vlan.Add(-1)
	}
}

func (t *pendingTable) has(k txKey) bool {
	s := t.shard(k)
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.entries[k]
	return ok
}

func (t *pendingTable) delete(k txKey) {
	s := t.shard(k)
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[k]; ok {
		t.removeLocked(s, k, e)
	}
}

func (t *pendingTable) sweepShard(idx int) {
	s := &t.shards[idx]
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.entries {
		if now.After(e.expiresAt) {
			t.removeLocked(s, k, e)
		}
	}
}

// runSweeper visits one shard every EntryTTL/ShardCount, completing a full
// pass over all ShardCount shards every EntryTTL.
func (t *pendingTable) runSweeper(stop <-chan struct{}) {
	ticker := time.NewTicker(sweepInterval())
	defer ticker.Stop()

	idx := 0
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			t.sweepShard(idx)
			idx = (idx + 1) % ShardCount
		}
	}
}

func sweepInterval() time.Duration {
	return EntryTTL / ShardCount
}
