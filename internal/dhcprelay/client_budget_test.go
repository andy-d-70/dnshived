// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dhcprelay

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestClientLimiter_RelayWideBudgetCapsAllVLANs(t *testing.T) {
	var budget atomic.Int64
	now := time.Unix(1_800_000_000, 0)
	perVLAN := maxTrackedClientsTotal / maxTrackedClients
	limiters := make([]*clientLimiter, perVLAN+1)
	for i := range limiters {
		limiters[i] = newClientLimiter(&budget)
	}
	for i := 0; i < perVLAN; i++ {
		for j := 0; j < maxTrackedClients; j++ {
			mac := [6]byte{byte(i), byte(j >> 8), byte(j)}
			if v := limiters[i].allow(now, mac, 10, 20); v != clientAllowed {
				t.Fatalf("vlan %d client %d: %v", i, j, v)
			}
		}
	}
	if got := budget.Load(); got != maxTrackedClientsTotal {
		t.Fatalf("budget = %d, want %d", got, maxTrackedClientsTotal)
	}
	last := limiters[perVLAN]
	if v := last.allow(now, [6]byte{0xff}, 10, 20); v != clientTableFull {
		t.Fatalf("over relay-wide cap: got %v, want clientTableFull", v)
	}
	if got := budget.Load(); got != maxTrackedClientsTotal {
		t.Fatalf("budget leaked on refusal: %d", got)
	}
}

func TestClientLimiter_IdleSweepAtMostOncePerSecond(t *testing.T) {
	cl := newClientLimiter(new(atomic.Int64))
	t0 := time.Unix(1_800_000_000, 0)
	for j := 0; j < maxTrackedClients; j++ {
		cl.allow(t0, [6]byte{byte(j >> 8), byte(j)}, 10, 20)
	}
	t1 := t0.Add(clientIdleAfter)
	if v := cl.allow(t1, [6]byte{0xff, 0xff}, 10, 20); v != clientAllowed {
		t.Fatalf("first sweep: got %v, want clientAllowed", v)
	}
	cl.buckets[[6]byte{0xee, 0xee}] = &clientBucket{tokens: 20, last: t0}
	if v := cl.allow(t1.Add(500*time.Millisecond), [6]byte{0xdd, 0xdd}, 10, 20); v != clientAllowed {
		t.Fatalf("within the throttle window the table has room, got %v", v)
	}
	for len(cl.buckets) < maxTrackedClients {
		cl.buckets[[6]byte{0xcc, byte(len(cl.buckets)), byte(len(cl.buckets) >> 8)}] = &clientBucket{tokens: 20, last: t1}
	}
	if v := cl.allow(t1.Add(500*time.Millisecond), [6]byte{0xbb, 0xbb}, 10, 20); v != clientTableFull {
		t.Fatalf("throttled sweep: got %v, want clientTableFull", v)
	}
	if v := cl.allow(t1.Add(time.Second), [6]byte{0xbb, 0xbb}, 10, 20); v != clientAllowed {
		t.Fatalf("after the throttle window: got %v, want clientAllowed", v)
	}
}
