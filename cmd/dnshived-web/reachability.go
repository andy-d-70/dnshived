// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"errors"
	"strings"
	"sync"
	"syscall"
	"time"
)

// deadRecheckInterval is how long a dead mark short-circuits requests
// before one real dial is tried again.
const deadRecheckInterval = 20 * time.Second

// deadStreakThreshold consecutive dial failures mark an address dead.
const deadStreakThreshold = 2

// nodeReachability caches which node addresses are believed dead, so a
// page load does not pay a dial timeout for each of them.
type nodeReachability struct {
	mu   sync.RWMutex
	dead map[string]time.Time
	// fallback maps a dead node's mgmt address to its scope-VLAN fallback
	// address, as reported by reachable peers.
	fallback   map[string]string
	failStreak map[string]int
}

var reachability = &nodeReachability{dead: make(map[string]time.Time), fallback: make(map[string]string), failStreak: make(map[string]int)}

// isDead reports whether addr is currently believed unreachable AND its
// last mark is still within deadRecheckInterval.
func (r *nodeReachability) isDead(addr string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	since, marked := r.dead[addr]
	if !marked {
		return false
	}
	return time.Since(since) < deadRecheckInterval || r.fallback[addr] != ""
}

// fallbackFor returns the fallback address a believed-dead node is
// currently reachable on, or "".
func (r *nodeReachability) fallbackFor(addr string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.fallback[addr]
}

// viaFallback reports whether fetches to addr are currently being
// tunnelled over its fallback address (dead over mgmt, route known).
func (r *nodeReachability) viaFallback(addr string) bool {
	return r.isDead(addr) && r.fallbackFor(addr) != ""
}

func (r *nodeReachability) markDead(addr string) {
	r.mu.Lock()
	r.failStreak[addr]++
	if r.failStreak[addr] >= deadStreakThreshold {
		r.dead[addr] = time.Now()
	}
	r.mu.Unlock()
}

// countsAsDead is false for a refused connection: it fails instantly, so
// caching it saves nothing, and it is what a node that is still starting
// returns.
func countsAsDead(err error) bool {
	return !errors.Is(err, syscall.ECONNREFUSED)
}

func countsAsDeadMsg(msg string) bool {
	return !strings.Contains(msg, "connection refused")
}

func (r *nodeReachability) markAlive(addr string) {
	r.mu.Lock()
	delete(r.dead, addr)
	delete(r.fallback, addr)
	delete(r.failStreak, addr)
	r.mu.Unlock()
}

// observePeerReport folds a reached node's view of its peers into the
// cache; a peer reported visible again clears its dead mark.
func (r *nodeReachability) observePeerReport(visible, unreachable []string, fallbackPeers map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, addr := range unreachable {
		if _, already := r.dead[addr]; !already {
			r.dead[addr] = time.Now()
		}
		if fb, ok := fallbackPeers[addr]; ok && fb != "" {
			r.fallback[addr] = fb
		} else {
			delete(r.fallback, addr)
		}
	}
	for _, addr := range visible {
		delete(r.dead, addr)
		delete(r.fallback, addr)
	}
}
