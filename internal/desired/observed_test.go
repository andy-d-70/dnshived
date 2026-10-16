package desired

import (
	"testing"
	"time"

	"dnshived/internal/fsm"
)

func ownerOf(m Map, scope string) string {
	for _, a := range m.Assignments {
		if a.Scope == scope {
			return a.Owner
		}
	}
	return ""
}

func splitFixture(t *testing.T) (core1Engine, core3Engine *Engine, live WorkerLiveness) {
	t.Helper()
	scopes := []ScopeDefinition{{Name: "siuf", PreferredWorker: "core-3", Parent: "ens20"}}

	core1Engine = New(0, scopes, 60*time.Second, 0)
	core1Engine.Reconcile(fsm.StateStable, WorkerLiveness{Core1Alive: true}, 0)

	core3Engine = New(0, scopes, 60*time.Second, 0)
	return core1Engine, core3Engine, WorkerLiveness{Core1Alive: true, Core3Alive: true}
}

func TestEngine_DifferentHistoriesSplitWithoutObserved(t *testing.T) {
	a, b, live := splitFixture(t)
	if got := ownerOf(a.Reconcile(fsm.StateStable, live, 0), "siuf"); got != "core-1" {
		t.Fatalf("core-1's engine = %q, want core-1 (holding its own history)", got)
	}
	if got := ownerOf(b.Reconcile(fsm.StateStable, live, 0), "siuf"); got != "core-3" {
		t.Fatalf("core-3's fresh engine = %q, want core-3 (no history)", got)
	}
}

func TestEngine_ObservedServingMakesDifferentHistoriesAgree(t *testing.T) {
	a, b, live := splitFixture(t)
	live.Observed = ObservedServing(map[string][]string{"core-1": {"siuf"}})

	for i := 0; i < 3; i++ {
		ga := ownerOf(a.Reconcile(fsm.StateStable, live, 0), "siuf")
		gb := ownerOf(b.Reconcile(fsm.StateStable, live, 0), "siuf")
		if ga != gb || ga != "core-1" {
			t.Fatalf("tick %d: core-1's engine = %q, core-3's engine = %q, want both core-1", i, ga, gb)
		}
	}
}

func TestEngine_ObservedOwnerDeadFallsThrough(t *testing.T) {
	_, b, _ := splitFixture(t)
	live := WorkerLiveness{Core3Alive: true, Observed: CurrentServing{"siuf": "core-1"}}
	if got := ownerOf(b.Reconcile(fsm.StateStable, live, 0), "siuf"); got != "core-3" {
		t.Errorf("owner = %q, want core-3: a dead observed owner must not be held", got)
	}
}

func TestObservedServing_OverlapResolvesDeterministically(t *testing.T) {
	got := ObservedServing(map[string][]string{
		"core-3": {"a", "b"},
		"core-1": {"a"},
	})
	if got["a"] != "core-1" || got["b"] != "core-3" {
		t.Errorf("ObservedServing = %v, want a->core-1 (coreRoleOrder), b->core-3", got)
	}
}
