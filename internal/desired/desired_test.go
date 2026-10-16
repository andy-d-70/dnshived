// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package desired

import (
	"fmt"
	"testing"
	"time"

	"dnshived/internal/config"
)

// TestOwnerForStable_AllDead_Unowned covers rule 1: nobody alive at all,
// regardless of which role is preferred, must be unowned.
func TestOwnerForStable_AllDead_Unowned(t *testing.T) {
	live := WorkerLiveness{}
	for _, preferred := range coreRoleOrder {
		got := ownerForStable("test-scope", preferred, "", live, "", time.Time{})
		if got != OwnerNone {
			t.Errorf("preferred=%s: got owner %q, want unowned", preferred, got)
		}
	}
}

// TestOwnerForStable_PreferredAliveStable_ReturnsPreferred covers rule 2
// for all 3 roles.
func TestOwnerForStable_PreferredAliveStable_ReturnsPreferred(t *testing.T) {
	cases := []struct {
		preferred string
		live      WorkerLiveness
	}{
		{config.RoleCore1, WorkerLiveness{Core1Alive: true, Core1Stable: true, Core2Alive: true, Core3Alive: true}},
		{config.RoleCore2, WorkerLiveness{Core2Alive: true, Core2Stable: true, Core1Alive: true, Core3Alive: true}},
		{config.RoleCore3, WorkerLiveness{Core3Alive: true, Core3Stable: true, Core1Alive: true, Core2Alive: true}},
	}
	for _, c := range cases {
		got := ownerForStable("test-scope", c.preferred, "", c.live, "", time.Time{})
		if got != c.preferred {
			t.Errorf("preferred=%s: got owner %q, want %q", c.preferred, got, c.preferred)
		}
	}
}

func TestOwnerForStable_PreferredDead_SoleOtherAlive_Failover(t *testing.T) {
	cases := []struct {
		preferred string
		alive     string // the one other role that's alive
		live      WorkerLiveness
	}{
		{config.RoleCore1, config.RoleCore2, WorkerLiveness{Core2Alive: true}},
		{config.RoleCore1, config.RoleCore3, WorkerLiveness{Core3Alive: true}},
		{config.RoleCore2, config.RoleCore3, WorkerLiveness{Core3Alive: true}},
	}
	for _, c := range cases {
		got := ownerForStable("test-scope", c.preferred, "", c.live, "", time.Time{})
		if got != c.alive {
			t.Errorf("preferred=%s (dead), only %s alive: got owner %q, want %q",
				c.preferred, c.alive, got, c.alive)
		}
	}
}

func TestOwnerForStable_PreferredDead_BothOthersAlive_HoldsCurrentServer(t *testing.T) {
	live := WorkerLiveness{Core2Alive: true, Core3Alive: true} // core-1 dead
	// core-3 is already serving — coreRoleOrder would pick core-2 first
	// if this test didn't specifically prove the hold takes priority.
	got := ownerForStable("test-scope", config.RoleCore1, "", live, config.RoleCore3, time.Time{})
	if got != config.RoleCore3 {
		t.Errorf("got owner %q, want core-3 held (was already serving)", got)
	}
}

func TestOwnerForStable_PreferredDead_BothOthersAlive_NoCurrentOwner_DeterministicPick(t *testing.T) {
	live := WorkerLiveness{Core2Alive: true, Core3Alive: true} // core-1 dead
	got := ownerForStable("test-scope", config.RoleCore1, "", live, "", time.Time{})
	if got != config.RoleCore2 && got != config.RoleCore3 {
		t.Fatalf("got owner %q, want core-2 or core-3 (both alive, one of them must be picked)", got)
	}
	for i := 0; i < 20; i++ {
		again := ownerForStable("test-scope", config.RoleCore1, "", live, "", time.Time{})
		if again != got {
			t.Fatalf("ownerForStable(\"test-scope\", ...) = %q on repeat call %d, want the same %q every time", again, i, got)
		}
	}
}

func TestOwnerForStable_LoadSpreadsAcrossLiveOthers(t *testing.T) {
	live := WorkerLiveness{Core1Alive: true, Core3Alive: true} // core-2 dead
	got := map[string]int{}
	for i := 0; i < 50; i++ {
		scope := fmt.Sprintf("rand-ens19-%04d", i)
		owner := ownerForStable(scope, config.RoleCore2, "", live, "", time.Time{})
		got[owner]++
	}
	if got[config.RoleCore1] == 0 || got[config.RoleCore3] == 0 {
		t.Fatalf("owner distribution across 50 scopes = %v, want both core-1 and core-3 to receive at least one (real load spreading, not always the same fixed candidate)", got)
	}
}

func TestOwnerForStable_PreferredAliveNotStable_OtherServing_Holds(t *testing.T) {
	live := WorkerLiveness{Core1Alive: true, Core1Stable: false, Core2Alive: true, Core3Alive: true}
	got := ownerForStable("test-scope", config.RoleCore1, "", live, config.RoleCore3, time.Time{})
	if got != config.RoleCore3 {
		t.Errorf("got owner %q, want core-3 held (currently serving, preferred not yet stable)", got)
	}
}

func TestOwnerForStable_PreferredAliveNotStable_NobodyServing_EmergencyAssignsPreferred(t *testing.T) {
	live := WorkerLiveness{Core1Alive: true, Core1Stable: false, Core2Alive: true, Core3Alive: true}
	got := ownerForStable("test-scope", config.RoleCore1, "", live, "", time.Time{})
	if got != config.RoleCore1 {
		t.Errorf("got owner %q, want core-1 (emergency assignment, nobody else serving)", got)
	}
}

func TestCompute_ScopePreferringCore3_FullyAssignable(t *testing.T) {
	scopes := []ScopeDefinition{{Name: "dante", PreferredWorker: config.RoleCore3}}
	live := WorkerLiveness{Core1Alive: true, Core2Alive: true, Core3Alive: true, Core3Stable: true}
	got := Compute(scopes, live, CurrentServing{})
	if len(got) != 1 || got[0].Owner != config.RoleCore3 {
		t.Fatalf("Compute() = %+v, want exactly one assignment owned by core-3", got)
	}
}

// TestCompute_DeterministicAcrossRepeatedCalls confirms identical inputs
// always produce byte-identical output.
func TestCompute_DeterministicAcrossRepeatedCalls(t *testing.T) {
	scopes := []ScopeDefinition{
		{Name: "office", PreferredWorker: config.RoleCore1},
		{Name: "av-dante", PreferredWorker: config.RoleCore2},
		{Name: "iot", PreferredWorker: config.RoleCore3},
	}
	live := WorkerLiveness{Core1Alive: true, Core2Alive: true} // core-3 dead
	current := CurrentServing{"iot": config.RoleCore1}

	first := Compute(scopes, live, current)
	for i := 0; i < 20; i++ {
		again := Compute(scopes, live, current)
		if !Equal(first, again) {
			t.Fatalf("Compute() produced a different result on repeat call %d: %+v vs %+v", i, first, again)
		}
	}
}

func TestWorkerLiveness_TrunkHealthy(t *testing.T) {
	live := WorkerLiveness{
		TrunkHealth: map[string]map[string]bool{
			config.RoleCore1: {"ens19": false, "ens20": true},
		},
	}
	cases := []struct {
		name   string
		role   string
		parent string
		want   bool
	}{
		{"known unhealthy", config.RoleCore1, "ens19", false},
		{"known healthy", config.RoleCore1, "ens20", true},
		{"empty parent -- nothing to check", config.RoleCore1, "", true},
		{"parent absent for a known role", config.RoleCore1, "ens99", true},
		{"role never reported at all", config.RoleCore2, "ens19", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := live.trunkHealthy(c.role, c.parent); got != c.want {
				t.Errorf("trunkHealthy(%q, %q) = %v, want %v", c.role, c.parent, got, c.want)
			}
		})
	}
}

func TestWorkerLiveness_AliveForScope(t *testing.T) {
	live := WorkerLiveness{
		Core1Alive: true,
		TrunkHealth: map[string]map[string]bool{
			config.RoleCore1: {"ens19": false},
		},
	}
	if !live.alive(config.RoleCore1) {
		t.Fatal("sanity: core-1 must be alive() in this fixture")
	}
	if live.aliveForScope(config.RoleCore1, "ens19") {
		t.Error("aliveForScope(core-1, ens19) = true, want false (trunk down for this specific scope's parent)")
	}
	if !live.aliveForScope(config.RoleCore1, "ens20") {
		t.Error("aliveForScope(core-1, ens20) = false, want true (a different, unreported/healthy trunk)")
	}
	if !live.aliveForScope(config.RoleCore1, "") {
		t.Error("aliveForScope(core-1, \"\") = false, want true (no parent to check at all)")
	}
}

func TestOwnerForStable_PreferredAliveStable_OtherAlreadyServing_HoldsWithoutApproval(t *testing.T) {
	live := WorkerLiveness{
		Core1Alive: true, Core1Stable: true, Core1AliveSince: time.Now().Add(-2 * time.Minute),
		Core2Alive: true, Core3Alive: true,
	}
	got := ownerForStable("test-scope", config.RoleCore1, "", live, config.RoleCore3, time.Time{})
	if got != config.RoleCore3 {
		t.Errorf("got owner %q, want core-3 held (already serving, no operator-approved rebalance)", got)
	}
}

func TestOwnerForStable_PreferredAliveStable_ApprovedAfterAliveSince_Reclaims(t *testing.T) {
	aliveSince := time.Now().Add(-2 * time.Minute)
	live := WorkerLiveness{
		Core1Alive: true, Core1Stable: true, Core1AliveSince: aliveSince,
		Core2Alive: true, Core3Alive: true,
	}
	approvedAt := aliveSince.Add(time.Second) // approved just after coming alive
	got := ownerForStable("test-scope", config.RoleCore1, "", live, config.RoleCore3, approvedAt)
	if got != config.RoleCore1 {
		t.Errorf("got owner %q, want core-1 (operator approved a rebalance after this aliveness window started)", got)
	}
}

func TestOwnerForStable_PreferredAliveStable_StaleApprovalBeforeAliveSince_StillHolds(t *testing.T) {
	aliveSince := time.Now().Add(-2 * time.Minute)
	live := WorkerLiveness{
		Core1Alive: true, Core1Stable: true, Core1AliveSince: aliveSince,
		Core2Alive: true, Core3Alive: true,
	}
	staleApproval := aliveSince.Add(-time.Hour) // approved long before THIS uptime window
	got := ownerForStable("test-scope", config.RoleCore1, "", live, config.RoleCore3, staleApproval)
	if got != config.RoleCore3 {
		t.Errorf("got owner %q, want core-3 held (the approval predates this aliveness window, so it's stale)", got)
	}
}

// TestOwnerForStable_PreferredAliveStable_NobodyElseServing_ClaimsWithoutApproval
// confirms the gate only ever applies when there's something real to hold
// onto.
func TestOwnerForStable_PreferredAliveStable_NobodyElseServing_ClaimsWithoutApproval(t *testing.T) {
	live := WorkerLiveness{Core1Alive: true, Core1Stable: true, Core1AliveSince: time.Now().Add(-2 * time.Minute)}
	got := ownerForStable("test-scope", config.RoleCore1, "", live, "", time.Time{})
	if got != config.RoleCore1 {
		t.Errorf("got owner %q, want core-1 (nothing being held onto — ordinary assignment, not a rebalance)", got)
	}
}

// TestOwnerForStable_PreferredIsAlreadyCurrentOwner_NoApprovalNeeded
// confirms the gate never applies when preferred already owns the scope.
func TestOwnerForStable_PreferredIsAlreadyCurrentOwner_NoApprovalNeeded(t *testing.T) {
	live := WorkerLiveness{
		Core1Alive: true, Core1Stable: true, Core1AliveSince: time.Now().Add(-2 * time.Minute),
		Core2Alive: true, Core3Alive: true,
	}
	got := ownerForStable("test-scope", config.RoleCore1, "", live, config.RoleCore1, time.Time{})
	if got != config.RoleCore1 {
		t.Errorf("got owner %q, want core-1 (already the current owner, nothing to gate)", got)
	}
}

func TestScopesFromConfig_ConvertsRebalanceApprovedAt(t *testing.T) {
	now := time.Now().Unix()
	scopes := map[string]config.ScopeConfig{
		"approved": {PreferredWorker: config.RoleCore1, RebalanceApprovedAt: now},
		"never":    {PreferredWorker: config.RoleCore2},
	}
	out := ScopesFromConfig(scopes)
	byName := map[string]ScopeDefinition{}
	for _, sd := range out {
		byName[sd.Name] = sd
	}
	if got := byName["approved"].RebalanceApprovedAt.Unix(); got != now {
		t.Errorf("approved scope: RebalanceApprovedAt.Unix() = %d, want %d", got, now)
	}
	if !byName["never"].RebalanceApprovedAt.IsZero() {
		t.Errorf("never-approved scope: RebalanceApprovedAt = %v, want the zero time.Time", byName["never"].RebalanceApprovedAt)
	}
}

func TestOwnerForStable_PreferredTrunkDown_HandsOffToLiveOther(t *testing.T) {
	live := WorkerLiveness{
		Core1Alive: true, Core1Stable: true,
		Core2Alive: true, Core2Stable: true,
		TrunkHealth: map[string]map[string]bool{
			config.RoleCore1: {"ens19": false},
		},
	}
	got := ownerForStable("office", config.RoleCore1, "ens19", live, "", time.Time{})
	if got != config.RoleCore2 {
		t.Errorf("ownerForStable() = %q, want core-2 (core-1's own trunk to this scope is down)", got)
	}
}
