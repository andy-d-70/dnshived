// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dhcprelay

import (
	"sync"
	"sync/atomic"
	"time"
)

// defaultRateLimit/defaultRateBurst match cmd/dnshived-dnsrelay's own
// defaults exactly (100/s, burst 200).
const (
	defaultRateLimit = 100
	defaultRateBurst = defaultRateLimit * 2

	defaultPendingPerVLAN  = 2048
	defaultClientRateLimit = 10
	defaultClientRateBurst = 20

	maxTrackedClients      = 1024
	maxTrackedClientsTotal = 16384
	clientIdleAfter        = time.Minute
	clientEvictEvery       = time.Second
)

// resolveOptionalLimit maps a config value to its effective limit: 0 is
// def, negative is off (0).
func resolveOptionalLimit(v, def int) int {
	switch {
	case v == 0:
		return def
	case v < 0:
		return 0
	default:
		return v
	}
}

// resolveRateLimit/resolveRateBurst resolve one client interface's own
// effective rate/burst.
func resolveRateLimit(perInterface, clusterWide int) int {
	if perInterface > 0 {
		return perInterface
	}
	if clusterWide > 0 {
		return clusterWide
	}
	return defaultRateLimit
}

func resolveRateBurst(perInterface, clusterWide, resolvedRate int) int {
	if perInterface > 0 {
		return perInterface
	}
	if clusterWide > 0 {
		return clusterWide
	}
	return resolvedRate * 2
}

// tokenBucket is a plain, mutex-guarded token bucket.
type tokenBucket struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func newTokenBucket(burst int) *tokenBucket {
	return &tokenBucket{tokens: float64(burst), last: time.Now()}
}

// allow reports whether one more request may proceed right now, consuming
// a token if so.
func (tb *tokenBucket) allow(now time.Time, rate, burst int) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	elapsed := now.Sub(tb.last).Seconds()
	tb.last = now
	tb.tokens += elapsed * float64(rate)
	if tb.tokens > float64(burst) {
		tb.tokens = float64(burst)
	}
	if tb.tokens >= 1.0 {
		tb.tokens--
		return true
	}
	return false
}

type clientLimiter struct {
	mu        sync.Mutex
	buckets   map[[6]byte]*clientBucket
	budget    *atomic.Int64
	lastEvict time.Time
}

type clientBucket struct {
	tokens float64
	last   time.Time
}

func newClientLimiter(budget *atomic.Int64) *clientLimiter {
	return &clientLimiter{buckets: make(map[[6]byte]*clientBucket), budget: budget}
}

type clientVerdict int

const (
	clientAllowed clientVerdict = iota
	clientLimited
	clientTableFull // allowed: the table could not track this client
)

func (cl *clientLimiter) allow(now time.Time, mac [6]byte, rate, burst int) clientVerdict {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	b, ok := cl.buckets[mac]
	if !ok {
		if !cl.claim() {
			if now.Sub(cl.lastEvict) >= clientEvictEvery {
				cl.lastEvict = now
				cl.evictIdle(now)
			}
			if !cl.claim() {
				return clientTableFull
			}
		}
		b = &clientBucket{tokens: float64(burst), last: now}
		cl.buckets[mac] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * float64(rate)
	b.last = now
	if b.tokens > float64(burst) {
		b.tokens = float64(burst)
	}
	if b.tokens >= 1.0 {
		b.tokens--
		return clientAllowed
	}
	return clientLimited
}

func (cl *clientLimiter) claim() bool {
	if len(cl.buckets) >= maxTrackedClients {
		return false
	}
	if cl.budget.Add(1) > maxTrackedClientsTotal {
		cl.budget.Add(-1)
		return false
	}
	return true
}

func (cl *clientLimiter) evictIdle(now time.Time) {
	for mac, b := range cl.buckets {
		if now.Sub(b.last) >= clientIdleAfter {
			delete(cl.buckets, mac)
			cl.budget.Add(-1)
		}
	}
}
