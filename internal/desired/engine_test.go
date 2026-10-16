// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package desired

import (
	"sync"
	"testing"
	"time"

	"dnshived/internal/config"
	"dnshived/internal/fsm"
)

func testScopes() []ScopeDefinition {
	return []ScopeDefinition{
		{Name: "office", PreferredWorker: config.RoleCore1},
		{Name: "av-dante", PreferredWorker: config.RoleCore2},
	}
}

func TestEngine_NonStableFreezesGeneration(t *testing.T) {
	e := New(0, testScopes(), 60*time.Second, 0)
	m := e.Reconcile(fsm.StateDegraded, WorkerLiveness{Core1Alive: true, Core2Alive: true}, 0)
	if m.Authoritative {
		t.Fatal("a non-STABLE state must never be authoritative")
	}
	if m.Generation != 0 {
		t.Fatalf("generation must stay frozen when not STABLE, got %d", m.Generation)
	}
}

func TestEngine_StableBumpsGenerationOnFirstAuthority(t *testing.T) {
	e := New(0, testScopes(), 60*time.Second, 0)
	m := e.Reconcile(fsm.StateStable, WorkerLiveness{
		Core1Alive: true, Core1Stable: true,
		Core2Alive: true, Core2Stable: true,
	}, 0)
	if !m.Authoritative {
		t.Fatal("STABLE must be authoritative")
	}
	if m.Generation != 1 {
		t.Fatalf("expected generation 1 on first authoritative pass, got %d", m.Generation)
	}
}

func TestEngine_GenFloorFastForwardsWithoutDoubleBump(t *testing.T) {
	e := New(0, testScopes(), 60*time.Second, 0)
	live := WorkerLiveness{Core1Alive: true, Core1Stable: true, Core2Alive: true, Core2Stable: true}

	m := e.Reconcile(fsm.StateStable, live, 10)
	if m.Generation != 10 {
		t.Fatalf("expected floor fast-forward to land exactly at 10, got %d", m.Generation)
	}

	// Same inputs, no ownership change, no new floor — generation must hold.
	m2 := e.Reconcile(fsm.StateStable, live, 10)
	if m2.Generation != 10 {
		t.Fatalf("steady state must not bump generation, got %d", m2.Generation)
	}
}

func TestEngine_OwnedScopesEmptyWhenNotAuthoritative(t *testing.T) {
	e := New(0, testScopes(), 60*time.Second, 0)
	e.Reconcile(fsm.StateDegraded, WorkerLiveness{Core1Alive: true}, 0)
	owned, _ := e.OwnedScopes(config.RoleCore1)
	if owned != nil {
		t.Fatalf("expected no owned scopes while non-authoritative, got %v", owned)
	}
}

func TestEngine_ConcurrentReconcileStaysConsistent(t *testing.T) {
	e := New(0, testScopes(), 0, 0) // rebalanceDelay=0 so "stable" is immediate
	live := WorkerLiveness{Core1Alive: true, Core2Alive: true}

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			e.Reconcile(fsm.StateStable, live, 0)
		}()
	}
	wg.Wait()

	final := e.Snapshot()
	if !final.Authoritative {
		t.Fatal("expected authoritative after concurrent STABLE reconciles")
	}
	if final.Generation < 1 {
		t.Fatalf("expected generation to have advanced at least once, got %d", final.Generation)
	}
	before := e.Generation()
	e.Reconcile(fsm.StateStable, live, 0)
	if after := e.Generation(); after != before {
		t.Fatalf("steady state after concurrent settling still bumped: %d -> %d", before, after)
	}
}

func TestEngine_SetScopes_NewScopeBecomesAssignable(t *testing.T) {
	e := New(0, testScopes(), 60*time.Second, 0)
	live := WorkerLiveness{Core1Alive: true, Core1Stable: true, Core2Alive: true, Core2Stable: true}
	e.Reconcile(fsm.StateStable, live, 0)

	owned, _ := e.OwnedScopes(config.RoleCore1)
	for _, s := range owned {
		if s == "new-scope" {
			t.Fatal("new-scope must not be owned before SetScopes is ever called")
		}
	}

	e.SetScopes(append(testScopes(), ScopeDefinition{Name: "new-scope", PreferredWorker: config.RoleCore1}))
	e.Reconcile(fsm.StateStable, live, 0)

	owned, _ = e.OwnedScopes(config.RoleCore1)
	found := false
	for _, s := range owned {
		if s == "new-scope" {
			found = true
		}
	}
	if !found {
		t.Errorf("new-scope not owned by worker-a after SetScopes+Reconcile, owned=%v", owned)
	}
}

func TestEngine_SetScopes_EmptyFallsBackToDefaultScopes(t *testing.T) {
	e := New(0, testScopes(), 60*time.Second, 0)
	e.SetScopes(nil)
	live := WorkerLiveness{Core1Alive: true, Core1Stable: true}
	e.Reconcile(fsm.StateStable, live, 0)

	owned, _ := e.OwnedScopes(config.RoleCore1)
	if len(owned) == 0 {
		t.Error("SetScopes(nil) should fall back to DefaultScopes(), got zero owned scopes")
	}
}

// trunkScopes is a single-scope fixture with a real Parent, for the
// trunk-health debounce tests below.
func trunkScopes() []ScopeDefinition {
	return []ScopeDefinition{
		{Name: "office", PreferredWorker: config.RoleCore1, Parent: "ens19"},
	}
}

func TestEngine_Reconcile_TrunkDownDoesNotImmediatelyHandOff(t *testing.T) {
	e := New(0, trunkScopes(), 0, 5*time.Second) // a real, generous grace period
	live := WorkerLiveness{
		Core1Alive: true,
		Core2Alive: true,
		TrunkHealth: map[string]map[string]bool{
			config.RoleCore1: {"ens19": false}, // just went down, raw
		},
	}
	m := e.Reconcile(fsm.StateStable, live, 0)
	if len(m.Assignments) != 1 || m.Assignments[0].Owner != config.RoleCore1 {
		t.Fatalf("assignments = %v, want office still owned by core-1 (debounce not yet elapsed)", m.Assignments)
	}
}

func TestEngine_Reconcile_TrunkDownHandsOffAfterGracePeriod(t *testing.T) {
	e := New(0, trunkScopes(), 0, 15*time.Millisecond)
	live := WorkerLiveness{
		Core1Alive: true,
		Core2Alive: true,
		TrunkHealth: map[string]map[string]bool{
			config.RoleCore1: {"ens19": false},
		},
	}
	// First tick: within grace, still core-1.
	m := e.Reconcile(fsm.StateStable, live, 0)
	if m.Assignments[0].Owner != config.RoleCore1 {
		t.Fatalf("first tick: owner = %q, want core-1 (still within grace)", m.Assignments[0].Owner)
	}
	time.Sleep(25 * time.Millisecond) // past the 15ms grace period
	m = e.Reconcile(fsm.StateStable, live, 0)
	if m.Assignments[0].Owner != config.RoleCore2 {
		t.Fatalf("second tick (past grace): owner = %q, want core-2 (handed off)", m.Assignments[0].Owner)
	}
}

func TestEngine_Reconcile_TrunkRecoveryStillHoldsWithoutApproval(t *testing.T) {
	e := New(0, trunkScopes(), 5*time.Millisecond, 10*time.Millisecond)
	down := WorkerLiveness{
		Core1Alive:  true,
		Core2Alive:  true,
		TrunkHealth: map[string]map[string]bool{config.RoleCore1: {"ens19": false}},
	}
	e.Reconcile(fsm.StateStable, down, 0)
	time.Sleep(20 * time.Millisecond) // past both the 5ms rebalanceDelay and the 10ms grace period
	m := e.Reconcile(fsm.StateStable, down, 0)
	if m.Assignments[0].Owner != config.RoleCore2 {
		t.Fatalf("owner = %q, want core-2 (handed off past grace)", m.Assignments[0].Owner)
	}

	// Recovery: raw healthy again.
	up := down
	up.TrunkHealth = map[string]map[string]bool{config.RoleCore1: {"ens19": true}}
	m = e.Reconcile(fsm.StateStable, up, 0)
	if m.Assignments[0].Owner != config.RoleCore2 {
		t.Fatalf("owner = %q, want core-2 still held (trunk recovered, but no operator-approved rebalance yet)", m.Assignments[0].Owner)
	}
}

// TestEngine_Reconcile_TrunkRecoveryReclaimsOnceApproved is the same
// scenario as the test immediately above, but with an operator-approved
// rebalance in place.
func TestEngine_Reconcile_TrunkRecoveryReclaimsOnceApproved(t *testing.T) {
	e := New(0, trunkScopes(), 5*time.Millisecond, 10*time.Millisecond)
	down := WorkerLiveness{
		Core1Alive:  true,
		Core2Alive:  true,
		TrunkHealth: map[string]map[string]bool{config.RoleCore1: {"ens19": false}},
	}
	e.Reconcile(fsm.StateStable, down, 0)
	time.Sleep(20 * time.Millisecond)
	m := e.Reconcile(fsm.StateStable, down, 0)
	if m.Assignments[0].Owner != config.RoleCore2 {
		t.Fatalf("owner = %q, want core-2 (handed off past grace)", m.Assignments[0].Owner)
	}

	e.SetScopes([]ScopeDefinition{
		{Name: "office", PreferredWorker: config.RoleCore1, Parent: "ens19", RebalanceApprovedAt: time.Now()},
	})

	up := down
	up.TrunkHealth = map[string]map[string]bool{config.RoleCore1: {"ens19": true}}
	m = e.Reconcile(fsm.StateStable, up, 0)
	if m.Assignments[0].Owner != config.RoleCore1 {
		t.Fatalf("owner = %q, want core-1 (trunk recovered AND operator approved the rebalance)", m.Assignments[0].Owner)
	}
}

// TestEngine_Reconcile_UnknownTrunkHealthTreatedAsHealthy confirms a
// (role, parent) pair simply ABSENT from TrunkHealth never blocks that
// role from candidacy.
func TestEngine_Reconcile_UnknownTrunkHealthTreatedAsHealthy(t *testing.T) {
	e := New(0, trunkScopes(), 0, 0)
	live := WorkerLiveness{
		Core1Alive: true, Core1Stable: true,
	}
	m := e.Reconcile(fsm.StateStable, live, 0)
	if m.Assignments[0].Owner != config.RoleCore1 {
		t.Fatalf("owner = %q, want core-1 (unknown trunk health must not block a genuinely alive, stable candidate)", m.Assignments[0].Owner)
	}
}

func TestEngine_GraceFor_UnsetRangeFallsBackToFlat(t *testing.T) {
	e := New(0, trunkScopes(), 0, 20*time.Millisecond)
	scores := map[string]map[string]int{config.RoleCore1: {"ens19": 0}}
	if got := e.graceFor(config.RoleCore1, "ens19", scores); got != 20*time.Millisecond {
		t.Errorf("graceFor() = %v, want the flat 20ms (SetTrunkGraceRange never called)", got)
	}
}

func TestEngine_GraceFor_UnknownScoreFallsBackToFlat(t *testing.T) {
	e := New(0, trunkScopes(), 0, 20*time.Millisecond)
	e.SetTrunkGraceRange(10*time.Millisecond, 50*time.Millisecond)
	if got := e.graceFor(config.RoleCore1, "ens19", nil); got != 20*time.Millisecond {
		t.Errorf("graceFor() = %v, want the flat 20ms (no score at all)", got)
	}
	scores := map[string]map[string]int{config.RoleCore1: {"ens20": 90}} // different parent
	if got := e.graceFor(config.RoleCore1, "ens19", scores); got != 20*time.Millisecond {
		t.Errorf("graceFor() = %v, want the flat 20ms (parent not in scores)", got)
	}
}

// TestEngine_GraceFor_HighScoreGetsLongGrace confirms a highly trusted
// trunk (score near 100) gets close to graceMax.
func TestEngine_GraceFor_HighScoreGetsLongGrace(t *testing.T) {
	e := New(0, trunkScopes(), 0, 0)
	e.SetTrunkGraceRange(10*time.Second, 55*time.Second)
	scores := map[string]map[string]int{config.RoleCore1: {"ens19": 100}}
	got := e.graceFor(config.RoleCore1, "ens19", scores)
	if got != 55*time.Second {
		t.Errorf("graceFor() = %v, want 55s (score=100 -> graceMax exactly)", got)
	}
}

// TestEngine_GraceFor_LowScoreGetsShortGrace confirms a chronically
// unreliable trunk (score near 0) gets close to graceMin.
func TestEngine_GraceFor_LowScoreGetsShortGrace(t *testing.T) {
	e := New(0, trunkScopes(), 0, 0)
	e.SetTrunkGraceRange(10*time.Second, 55*time.Second)
	scores := map[string]map[string]int{config.RoleCore1: {"ens19": 0}}
	got := e.graceFor(config.RoleCore1, "ens19", scores)
	if got != 10*time.Second {
		t.Errorf("graceFor() = %v, want 10s (score=0 -> graceMin exactly)", got)
	}
}

// TestEngine_GraceFor_MidScoreInterpolatesLinearly confirms the formula is
// a real linear interpolation, not just correct at the two endpoints.
func TestEngine_GraceFor_MidScoreInterpolatesLinearly(t *testing.T) {
	e := New(0, trunkScopes(), 0, 0)
	e.SetTrunkGraceRange(10*time.Second, 60*time.Second)
	scores := map[string]map[string]int{config.RoleCore1: {"ens19": 50}}
	got := e.graceFor(config.RoleCore1, "ens19", scores)
	want := 35 * time.Second // 10 + (60-10)*0.5
	if got != want {
		t.Errorf("graceFor() = %v, want %v (linear midpoint)", got, want)
	}
}

func TestEngine_Reconcile_ContinuousGrace_LowScoreHandsOffFasterThanFlat(t *testing.T) {
	e := New(0, trunkScopes(), 0, 5*time.Second)
	e.SetTrunkGraceRange(1*time.Millisecond, 5*time.Second)
	live := WorkerLiveness{
		Core1Alive: true,
		Core2Alive: true,
		TrunkHealth: map[string]map[string]bool{
			config.RoleCore1: {"ens19": false},
		},
		TrunkScore: map[string]map[string]int{
			config.RoleCore1: {"ens19": 0}, // chronically unreliable
		},
	}
	e.Reconcile(fsm.StateStable, live, 0) // tick 1: establishes the down-transition
	time.Sleep(15 * time.Millisecond)     // past the near-zero score-derived grace, nowhere near the flat 5s
	m := e.Reconcile(fsm.StateStable, live, 0)
	if m.Assignments[0].Owner != config.RoleCore2 {
		t.Fatalf("owner = %q, want core-2 (low-score trunk hands off fast, not waiting out the flat 5s)", m.Assignments[0].Owner)
	}
}
