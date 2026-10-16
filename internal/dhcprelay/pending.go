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
	EntryTTL = 120 * time.Second

	// MaxPending bounds total memory regardless of TTL/sweep timing -- once
	// reached, addPending refuses new transactions rather than growing without
	// limit.
	MaxPending = 10000
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
	entries map[txKey]time.Time // value is expiresAt
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
		t.shards[i].entries = make(map[txKey]time.Time)
	}
	return t
}

func (t *pendingTable) shard(k txKey) *pendingShard {
	return &t.shards[k.xid%ShardCount]
}

func (t *pendingTable) add(k txKey) bool {
	s := t.shard(k)
	s.mu.Lock()
	defer s.mu.Unlock()

	_, exists := s.entries[k]
	if !exists && t.globalCnt.Load() >= MaxPending {
		return false
	}
	s.entries[k] = time.Now().Add(EntryTTL)
	if !exists {
		t.globalCnt.Add(1)
	}
	return true
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
	if _, ok := s.entries[k]; ok {
		delete(s.entries, k)
		t.globalCnt.Add(-1)
	}
}

func (t *pendingTable) sweepShard(idx int) {
	s := &t.shards[idx]
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, expiresAt := range s.entries {
		if now.After(expiresAt) {
			delete(s.entries, k)
			t.globalCnt.Add(-1)
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
