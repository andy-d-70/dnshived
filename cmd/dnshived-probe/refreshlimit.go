// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import "sync"

// refreshLimiter serializes on-demand "probe now" triggers per scope.
type refreshLimiter struct {
	mu       sync.Mutex
	inFlight map[string]bool
}

func newRefreshLimiter() *refreshLimiter {
	return &refreshLimiter{inFlight: make(map[string]bool)}
}

// tryStart reports whether scope was successfully claimed (true) or is
// already in flight (false).
func (l *refreshLimiter) tryStart(scope string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.inFlight[scope] {
		return false
	}
	l.inFlight[scope] = true
	return true
}

func (l *refreshLimiter) finish(scope string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.inFlight, scope)
}
