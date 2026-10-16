// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"log"
	"sync"
)

// dhcpProbeScheduler gives an on-demand "probe now" click priority over
// the background sweep's own round, per physical trunk (parent interface).
type dhcpProbeScheduler struct {
	mu      sync.Mutex
	workers map[string]*trunkQueue
}

func newDHCPProbeScheduler() *dhcpProbeScheduler {
	return &dhcpProbeScheduler{workers: make(map[string]*trunkQueue)}
}

// probeScheduler is the one instance every real caller (runProbeSweep,
// probeScopeNow) shares.
var probeScheduler = newDHCPProbeScheduler()

type trunkQueue struct {
	priority chan func()
	normal   chan func()
}

func newTrunkQueue() *trunkQueue {
	q := &trunkQueue{
		priority: make(chan func()),
		normal:   make(chan func()),
	}
	go q.run()
	return q
}

func (q *trunkQueue) run() {
	for {
		select {
		case fn := <-q.priority:
			fn()
			continue
		default:
		}
		select {
		case fn := <-q.priority:
			fn()
		case fn := <-q.normal:
			fn()
		}
	}
}

func (s *dhcpProbeScheduler) queueFor(trunk string) *trunkQueue {
	s.mu.Lock()
	defer s.mu.Unlock()
	q, ok := s.workers[trunk]
	if !ok {
		q = newTrunkQueue()
		s.workers[trunk] = q
	}
	return q
}

// Submit blocks until fn has actually run.
func (s *dhcpProbeScheduler) Submit(trunk string, priority bool, fn func()) {
	q := s.queueFor(trunk)
	done := make(chan struct{})
	wrapped := func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[PROBE:SCHED] panic in %s probe: %v", trunk, r)
			}
		}()
		fn()
	}
	if priority {
		q.priority <- wrapped
	} else {
		q.normal <- wrapped
	}
	<-done
}
