// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"sync"
	"testing"
	"time"
)

func TestTrunkQueue_PriorityRunsBeforeAlreadyQueuedNormalWork(t *testing.T) {
	s := newDHCPProbeScheduler()

	started := make(chan struct{})
	release := make(chan struct{})
	go s.Submit("ens19", false, func() {
		close(started)
		<-release
	})
	<-started // the worker is now busy running the "blocker" job

	var mu sync.Mutex
	var order []string
	record := func(name string) {
		mu.Lock()
		order = append(order, name)
		mu.Unlock()
	}

	// Queue three normal jobs first, THEN one priority job.
	var wg sync.WaitGroup
	var submitted sync.WaitGroup
	submitted.Add(4)
	for _, name := range []string{"normal-1", "normal-2", "normal-3"} {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			submitted.Done()
			s.Submit("ens19", false, func() { record(name) })
		}(name)
	}
	wg.Add(1)
	go func(name string) {
		defer wg.Done()
		submitted.Done()
		s.Submit("ens19", true, func() { record(name) })
	}("priority-1")

	submitted.Wait()
	time.Sleep(100 * time.Millisecond)
	close(release)

	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(order) != 4 {
		t.Fatalf("order = %v, want 4 entries", order)
	}
	if order[0] != "priority-1" {
		t.Errorf("first job to run after the blocker released = %q, want %q (priority must always run next, regardless of how many normal jobs were already queued)", order[0], "priority-1")
	}
}

// TestDHCPProbeScheduler_DifferentTrunksRunConcurrently confirms this
// scheduler doesn't accidentally reintroduce global (cross-trunk)
// serialization.
func TestDHCPProbeScheduler_DifferentTrunksRunConcurrently(t *testing.T) {
	s := newDHCPProbeScheduler()

	blockingA := make(chan struct{})
	releaseA := make(chan struct{})
	go s.Submit("ens19", false, func() {
		close(blockingA)
		<-releaseA
	})
	<-blockingA // ens19's worker is now busy

	// A job on a DIFFERENT trunk must complete promptly, never waiting
	// on ens19's own in-flight/queued work.
	done := make(chan struct{})
	go func() {
		s.Submit("ens20", false, func() {})
		close(done)
	}()

	select {
	case <-done:
		// correct — ens20 was never blocked by ens19's own busy worker
	case <-time.After(2 * time.Second):
		t.Fatal("a job on a different trunk (ens20) waited on ens19's own busy worker — trunks must be independent")
	}

	close(releaseA)
}

// TestDHCPProbeScheduler_SameTrunkNeverRunsConcurrently is the correctness
// property this scheduler must never weaken.
func TestDHCPProbeScheduler_SameTrunkNeverRunsConcurrently(t *testing.T) {
	s := newDHCPProbeScheduler()

	var mu sync.Mutex
	active := 0
	maxActive := 0
	track := func() {
		mu.Lock()
		active++
		if active > maxActive {
			maxActive = active
		}
		mu.Unlock()
		time.Sleep(5 * time.Millisecond)
		mu.Lock()
		active--
		mu.Unlock()
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		priority := i%2 == 0
		go func(priority bool) {
			defer wg.Done()
			s.Submit("ens19", priority, track)
		}(priority)
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if maxActive > 1 {
		t.Errorf("maxActive = %d, want 1 — two jobs on the same trunk ran concurrently", maxActive)
	}
}
