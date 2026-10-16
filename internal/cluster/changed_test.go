// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package cluster

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"dnshived/internal/identity"
)

func TestObserver_Changed_FiresOnReachableToUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	addr := srv.Listener.Addr().String()

	self := identity.Identity{ClusterID: "test-cluster", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", []string{addr}, "")

	// First probe: initial discovery, not a transition — must not signal.
	o.probeAll()
	select {
	case <-o.Changed():
		t.Fatalf("Changed() fired on first-ever probe — initial discovery must not count as a transition")
	default:
	}

	// Take the peer down.
	srv.Close()
	o.probeAll()
	select {
	case <-o.Changed():
		t.Fatal("Changed() fired on a single failed probe — must be debounced (unreachableThreshold), not immediate")
	default:
	}

	// The next consecutive failure crosses the threshold: this IS a transition.
	o.probeAll()
	select {
	case <-o.Changed():
	case <-time.After(time.Second):
		t.Fatalf("Changed() did not fire after %d consecutive failed probes (unreachableThreshold)", unreachableThreshold)
	}
}

// TestObserver_Changed_FiresOnUnreachableToReachable covers the recovery
// direction.
func TestObserver_Changed_FiresOnUnreachableToReachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"cluster_id":"test-cluster","node_id":"peer-1","role":"core-2"}`))
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	self := identity.Identity{ClusterID: "test-cluster", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", []string{addr}, "")

	o.mu.Lock()
	o.peers[addr].Reachable = false
	o.peers[addr].Checks = 3
	o.mu.Unlock()

	o.probeAll()
	select {
	case <-o.Changed():
	case <-time.After(time.Second):
		t.Fatalf("Changed() did not fire on unreachable -> reachable transition")
	}
}

// TestObserver_Changed_NonBlockingUnderRepeatedSignals verifies the
// channel is a collapsing, buffer-1 signal.
func TestObserver_Changed_NonBlockingUnderRepeatedSignals(t *testing.T) {
	self := identity.Identity{ClusterID: "test-cluster", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 5; i++ {
			o.signalChanged()
		}
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("signalChanged() blocked under repeated calls with no consumer draining")
	}

	if len(o.changed) != 1 {
		t.Errorf("len(o.changed) = %d, want 1 — repeated signals before drain must collapse to one pending trigger", len(o.changed))
	}
}

func TestObserver_SetProbeInterval_ResetsLiveTicker(t *testing.T) {
	self := identity.Identity{ClusterID: "test-cluster", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")

	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	o.mu.Lock()
	o.probeTicker = ticker
	o.mu.Unlock()

	o.SetProbeInterval(10 * time.Millisecond)

	select {
	case <-ticker.C:
		// Reset took effect — the same ticker now fires on the new, short interval.
	case <-time.After(2 * time.Second):
		t.Error("ticker never fired within 2s of SetProbeInterval(10ms) — Reset did not take effect")
	}
}

// TestObserver_SetProbeInterval_NilTickerIsSafeNoOp covers the state
// before Start() has ever run.
func TestObserver_SetProbeInterval_NilTickerIsSafeNoOp(t *testing.T) {
	self := identity.Identity{ClusterID: "test-cluster", NodeID: "self", Role: "core-1"}
	o := NewObserver(self, "self-addr", nil, "")

	o.SetProbeInterval(5 * time.Second) // probeTicker is nil — must be a safe no-op, not a panic
}
