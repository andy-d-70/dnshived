// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"sync"
	"testing"
	"time"

	"dnshived/internal/config"
	"dnshived/internal/fencing"
	"dnshived/internal/fsm"
	"dnshived/internal/lease"
)

// testScopes returns a minimal single-scope config map.
func testScopes(name string) map[string]config.ScopeConfig {
	return map[string]config.ScopeConfig{
		name: {
			Parent:          "ens19",
			VLANID:          100,
			VIP:             "192.168.100.1/24",
			NodeIP:          "192.168.100.22/24",
			DHCPRange:       [2]string{"192.168.100.100", "192.168.100.200"},
			Gateway:         "192.168.100.1",
			VRRPID:          51,
			PreferredWorker: config.RoleCore1,
		},
	}
}

// validLease returns a HeldLeases map with a lease for scope that is valid
// and far from expiring — one of the four predicate conditions besides
// ownership.
func validLease(scope string, now int64) map[string]lease.Lease {
	return map[string]lease.Lease{
		scope: {
			Scope:     scope,
			Owner:     config.RoleCore1,
			ExpiresAt: now + 3600,
		},
	}
}

// allowedInputs returns ReconcileInputs under which every condition in
// scopeServeAllowed passes for scope: STABLE, owned, valid lease, token at
// watermark.
func allowedInputs(scope string) ReconcileInputs {
	now := time.Now().Unix()
	return ReconcileInputs{
		State:       fsm.StateStable,
		OwnedScopes: []string{scope},
		HeldLeases:  validLease(scope, now),
		SelfToken:   fencing.Token{Epoch: 1, Generation: 1},
		Watermark:   fencing.Token{Epoch: 1, Generation: 1},
		Now:         now,
	}
}

func TestGate_OpenRequiresWitness_DeniedWhenArbiterUnreachable(t *testing.T) {
	scope := "office"
	// psk != "" -> WitnessRequired=true.
	a := New(config.RoleCore1, "test-node", 1, "some-cluster-psk", "/tmp", testScopes(scope), nil)

	opened := a.openGate(scope, "test")

	if opened {
		t.Errorf("scope %q: openGate returned true, want false — witness could not be acquired (no arbiter reachable), gate must stay closed even though the predicate alone said allowed", scope)
	}
}

func TestSplitCloseOpenDecisions_SeparatesByDesiredServe(t *testing.T) {
	decisions := []gateDecision{
		{scope: "a", desired: DesiredAuthority{Serve: false}},
		{scope: "b", desired: DesiredAuthority{Serve: true}},
		{scope: "c", desired: DesiredAuthority{Serve: false}},
		{scope: "d", desired: DesiredAuthority{Serve: true}},
	}
	closes, opens := splitCloseOpenDecisions(decisions)

	if len(closes) != 2 || closes[0].scope != "a" || closes[1].scope != "c" {
		t.Errorf("closes = %+v, want [a c]", closes)
	}
	if len(opens) != 2 || opens[0].scope != "b" || opens[1].scope != "d" {
		t.Errorf("opens = %+v, want [b d]", opens)
	}
}

func TestSplitCloseOpenDecisions_EmptyInputProducesNilSlices(t *testing.T) {
	closes, opens := splitCloseOpenDecisions(nil)
	if len(closes) != 0 || len(opens) != 0 {
		t.Errorf("closes=%v opens=%v, want both empty for no decisions", closes, opens)
	}
}

func TestRunConcurrent_CallsEveryItemExactlyOnceAndWaits(t *testing.T) {
	items := make([]int, 200)
	for i := range items {
		items[i] = i
	}

	var mu sync.Mutex
	seen := make(map[int]int, len(items))
	runConcurrent(items, 16, func(item int) {
		time.Sleep(time.Millisecond) // real work takes real time
		mu.Lock()
		seen[item]++
		mu.Unlock()
	})

	if len(seen) != len(items) {
		t.Fatalf("len(seen) = %d, want %d — runConcurrent returned before every item ran", len(seen), len(items))
	}
	for item, count := range seen {
		if count != 1 {
			t.Errorf("item %d ran %d times, want exactly 1", item, count)
		}
	}
}

// TestRunConcurrent_NeverExceedsMaxConcurrency is the direct proof this is
// bounded, not a full per-item fan-out.
func TestRunConcurrent_NeverExceedsMaxConcurrency(t *testing.T) {
	const maxConcurrency = 4
	items := make([]int, 50)
	for i := range items {
		items[i] = i
	}

	var mu sync.Mutex
	current, peak := 0, 0
	runConcurrent(items, maxConcurrency, func(int) {
		mu.Lock()
		current++
		if current > peak {
			peak = current
		}
		mu.Unlock()

		time.Sleep(2 * time.Millisecond)

		mu.Lock()
		current--
		mu.Unlock()
	})

	if peak > maxConcurrency {
		t.Errorf("peak concurrent = %d, want <= %d", peak, maxConcurrency)
	}
	if peak < 2 {
		t.Errorf("peak concurrent = %d, want > 1 — this should actually run concurrently, not accidentally serialize", peak)
	}
}

// newTestAgent returns an agent set up as if ConstructPlane already ran
// successfully: every scope in a.ready, keepalivedReady set, past the
// settling window.
func newTestAgent(psk string, scopes map[string]config.ScopeConfig) *Agent {
	a := New(config.RoleCore1, "test-node", 1, psk, "/tmp", scopes, nil)
	a.stableSince = time.Unix(0, 0)
	a.lastState = fsm.StateStable
	for scope := range scopes {
		a.ready[scope] = time.Now()
	}
	a.keepalivedReady = true
	return a
}
