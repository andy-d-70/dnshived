// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"testing"

	"dnshived/internal/config"
	"dnshived/internal/reliability"
)

// TestReadCarrier_RealInterfaceReportsUp uses lo.
func TestReadCarrier_RealInterfaceReportsUp(t *testing.T) {
	up, ok := readCarrier("lo")
	if !ok {
		t.Fatal("readCarrier(\"lo\") ok = false, want true — lo must exist on any real host")
	}
	if !up {
		t.Error("readCarrier(\"lo\") up = false, want true — loopback always reports carrier up")
	}
}

func TestReadCarrier_NonexistentInterfaceReturnsNotOK(t *testing.T) {
	_, ok := readCarrier("definitely-not-a-real-iface-xyz")
	if ok {
		t.Error("readCarrier() on a nonexistent interface returned ok = true, want false")
	}
}

func TestCheckTrunkLinkState_HealthyTrunkNoFinding(t *testing.T) {
	scopes := testScopes("office")
	sc := scopes["office"]
	sc.Parent = "lo"
	scopes["office"] = sc
	a := newTestAgent("", scopes)

	found := a.checkTrunkLinkState()
	if len(found) != 0 {
		t.Errorf("checkTrunkLinkState() = %v, want no findings for a healthy trunk", found)
	}
	if a.trunkLinkDown["lo"] {
		t.Error("a.trunkLinkDown[\"lo\"] = true after a healthy check, want false")
	}
}

func TestCheckTrunkLinkState_UnknownInterfaceSkipped(t *testing.T) {
	scopes := testScopes("office")
	sc := scopes["office"]
	sc.Parent = "definitely-not-a-real-iface-xyz"
	scopes["office"] = sc
	a := newTestAgent("", scopes)

	found := a.checkTrunkLinkState()
	if len(found) != 0 {
		t.Errorf("checkTrunkLinkState() = %v, want no findings for a nonexistent interface (that's the \"interface\" finding's job)", found)
	}
}

func TestCheckTrunkLinkState_IncludesMgmtIfaceEvenWithNoScopes(t *testing.T) {
	a := newTestAgent("", map[string]config.ScopeConfig{})
	a.SetMgmtIface("lo")

	found := a.checkTrunkLinkState()
	if len(found) != 0 {
		t.Errorf("checkTrunkLinkState() = %v, want no findings for a healthy mgmt interface", found)
	}
	a.mu.Lock()
	_, checked := a.trunkLinkDown["lo"]
	down := a.trunkLinkDown["lo"]
	a.mu.Unlock()
	if !checked {
		t.Fatal("a.trunkLinkDown has no entry for \"lo\" — mgmtIface was never checked at all")
	}
	if down {
		t.Error("a.trunkLinkDown[\"lo\"] = true, want false (lo is always carrier-up)")
	}
}

func TestIsTrunkLinkDown_ReflectsCachedBelief(t *testing.T) {
	a := newTestAgent("", testScopes("office"))
	if a.isTrunkLinkDown("ens19") {
		t.Error("isTrunkLinkDown(\"ens19\") = true before any check ran, want false")
	}
	a.mu.Lock()
	a.trunkLinkDown["ens19"] = true
	a.mu.Unlock()
	if !a.isTrunkLinkDown("ens19") {
		t.Error("isTrunkLinkDown(\"ens19\") = false after being marked down, want true")
	}
}

func TestTrunkHealth_InvertsTrunkLinkDownExcludingMgmt(t *testing.T) {
	a := newTestAgent("", testScopes("office"))
	a.SetMgmtIface("mgmt0")
	a.mu.Lock()
	a.trunkLinkDown["ens19"] = false // up
	a.trunkLinkDown["ens20"] = true  // down
	a.trunkLinkDown["mgmt0"] = true  // down, but must never appear below
	a.mu.Unlock()

	got := a.TrunkHealth()
	want := map[string]bool{"ens19": true, "ens20": false}
	if len(got) != len(want) {
		t.Fatalf("TrunkHealth() = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("TrunkHealth()[%q] = %v, want %v", k, got[k], v)
		}
	}
	if _, ok := got["mgmt0"]; ok {
		t.Error("TrunkHealth() included the mgmt interface, want it excluded")
	}
}

func TestCheckTrunkLinkState_FeedsLocalTrunkReliability(t *testing.T) {
	a := newTestAgent("", testScopes("office"))
	a.SetMgmtIface("lo")
	a.checkTrunkLinkState()

	scores := a.LocalTrunkScores()
	if _, ok := scores["lo"]; ok {
		t.Error("LocalTrunkScores() included the mgmt interface, want it excluded")
	}
}

// TestLocalTrunkScores_ExcludesMgmtInterface mirrors
// TestTrunkHealth_InvertsTrunkLinkDownExcludingMgmt exactly, for
// LocalTrunkScores.
func TestLocalTrunkScores_ExcludesMgmtInterface(t *testing.T) {
	a := newTestAgent("", testScopes("office"))
	a.SetMgmtIface("mgmt0")
	a.checkTrunkLinkState() // no-op for made-up trunk names; seed directly instead
	a.trunkReliability.Observe("ens19", true)
	a.trunkReliability.Observe("mgmt0", true)

	got := a.LocalTrunkScores()
	if _, ok := got["ens19"]; !ok {
		t.Error("LocalTrunkScores() missing ens19")
	}
	if _, ok := got["mgmt0"]; ok {
		t.Error("LocalTrunkScores() included the mgmt interface, want it excluded")
	}
}

// TestResetTrunkReliability_ClearsHistory confirms the operator-facing
// reset action actually reaches the store.
func TestResetTrunkReliability_ClearsHistory(t *testing.T) {
	a := newTestAgent("", testScopes("office"))
	a.trunkReliability.Observe("ens19", false)
	a.trunkReliability.Observe("ens19", false)
	if got := a.LocalTrunkScores()["ens19"]; got == 100 {
		t.Fatalf("setup failed: expected a decayed score before reset")
	}

	a.ResetTrunkReliability("ens19")
	if got := a.trunkReliability.Observe("ens19", true); got != 100 {
		t.Errorf("first Observe(true) after reset = %d, want 100 (fresh start)", got)
	}
}

func TestTrunkReliabilitySnapshot_ReflectsRealObservations(t *testing.T) {
	a := newTestAgent("", testScopes("office"))
	a.trunkReliability.Observe("ens19", true)

	snap := a.TrunkReliabilitySnapshot()
	e, ok := snap["ens19"]
	if !ok || e.Score != 100 || !e.WasHealthy {
		t.Errorf("TrunkReliabilitySnapshot()[\"ens19\"] = %+v, %v, want Score=100 WasHealthy=true", e, ok)
	}
}

func TestRestoreTrunkReliability_ReplacesLocalHistory(t *testing.T) {
	a := newTestAgent("", testScopes("office"))
	a.trunkReliability.Observe("stale-trunk", false)
	a.trunkReliability.Observe("stale-trunk", false)

	a.RestoreTrunkReliability(map[string]reliability.Entry{
		"ens19": {Score: 61, WasHealthy: true},
	})

	snap := a.TrunkReliabilitySnapshot()
	if _, ok := snap["stale-trunk"]; ok {
		t.Error("RestoreTrunkReliability() left the pre-existing entry in place, want a full replace")
	}
	if e, ok := snap["ens19"]; !ok || e.Score != 61 {
		t.Errorf("TrunkReliabilitySnapshot()[\"ens19\"] after restore = %+v, ok=%v, want Score=61", e, ok)
	}
}
