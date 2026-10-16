// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dhcprelay

import (
	"sync"
	"time"
)

// defaultRateLimit/defaultRateBurst match cmd/dnshived-dnsrelay's own
// defaults exactly (100/s, burst 200).
const (
	defaultRateLimit = 100
	defaultRateBurst = defaultRateLimit * 2
)

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
func (tb *tokenBucket) allow(rate, burst int) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
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
