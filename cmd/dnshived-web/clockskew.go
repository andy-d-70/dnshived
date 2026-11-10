// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"log"
	"sync"
	"time"
)

const (
	clockSkewLimit      = 5 * time.Second
	clockSkewReadings   = 2
	clockSkewMaxTracked = 64
)

// clockSkewOutside is how far a node's reported time lies outside the window
// of the request that carried it. The node's time has second resolution, so
// it stands for [serverT, serverT+1s).
func clockSkewOutside(serverT, start, end time.Time) time.Duration {
	if start.IsZero() || start.After(end) {
		start = end
	}
	if upper := serverT.Add(time.Second); upper.Before(start) {
		return start.Sub(upper)
	}
	if serverT.After(end) {
		return serverT.Sub(end)
	}
	return 0
}

type skewState struct {
	lastReading time.Time
	strikes     int
	raised      bool
}

// skewTracker turns single skew readings into a debounced warning: it is
// raised after clockSkewReadings fresh readings in a row over the limit and
// clears on the first reading within it.
type skewTracker struct {
	mu    sync.Mutex
	nodes map[string]*skewState
}

var clockSkewTracker = &skewTracker{}

// observe records one reading and reports whether the warning is raised. A
// reading with the same stamp as the previous one is the same cached
// snapshot seen again and does not count twice.
func (t *skewTracker) observe(node string, reading time.Time, skew time.Duration, observer string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.nodes == nil || len(t.nodes) >= clockSkewMaxTracked {
		if _, known := t.nodes[node]; !known {
			t.nodes = make(map[string]*skewState)
		}
	}
	st := t.nodes[node]
	if st == nil {
		st = &skewState{}
		t.nodes[node] = st
	}
	if reading.Equal(st.lastReading) {
		return st.raised
	}
	st.lastReading = reading
	if skew > clockSkewLimit {
		st.strikes++
		if st.strikes >= clockSkewReadings && !st.raised {
			st.raised = true
			log.Printf("[CLOCK] skew raised: %q is %.1fs off from %s", node, skew.Seconds(), observer)
		}
		return st.raised
	}
	if st.raised {
		log.Printf("[CLOCK] skew cleared: %q is %.1fs off from %s", node, skew.Seconds(), observer)
	}
	st.strikes, st.raised = 0, false
	return false
}

// reset forgets every node; tests use it to start clean.
func (t *skewTracker) reset() {
	t.mu.Lock()
	t.nodes = nil
	t.mu.Unlock()
}
