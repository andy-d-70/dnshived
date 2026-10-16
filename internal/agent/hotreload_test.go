// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"strings"
	"testing"
	"time"

	"dnshived/internal/config"
)

func TestHotReloadScopes_ArbiterRoleTearsDownToo(t *testing.T) {
	updated := testScopes("office")
	sc := updated["office"]
	sc.VLANID = 200
	updated["office"] = sc

	worker := New(config.RoleCore1, "test-node", 1, "psk", t.TempDir(), testScopes("office"), nil)
	arb := New(config.RoleCore3, "test-node", 1, "psk", t.TempDir(), testScopes("office"), nil)

	workerReport := worker.HotReloadScopes(updated)
	arbReport := arb.HotReloadScopes(updated)
	if len(arbReport) != len(workerReport) {
		t.Errorf("HotReloadScopes report: arbiter = %v, worker = %v — every core role must behave identically now", arbReport, workerReport)
	}

	got, ok := arb.scopeConfig("office")
	if !ok || got.VLANID != 200 {
		t.Errorf("scopeConfig(office) = %+v, ok=%v, want VLANID=200 — arbiter must still publish the new map", got, ok)
	}
}

func TestHotReloadScopes_AddedScope_NotMarkedReady(t *testing.T) {
	dir := t.TempDir()
	a := New(config.RoleCore1, "test-node", 1, "psk", dir, nil, nil)

	updated := testScopes("office")
	report := a.HotReloadScopes(updated)

	if len(report) != 1 || !strings.Contains(report[0], "office: added") {
		t.Errorf("report = %v, want a single 'office: added' line", report)
	}
	if _, ok := a.scopeConfig("office"); !ok {
		t.Error("office missing from a.scopes after being added")
	}
	a.mu.Lock()
	_, ready := a.ready["office"]
	a.mu.Unlock()
	if ready {
		t.Error("a newly-added scope must NOT be marked ready — it needs real construction first")
	}
}

// TestHotReloadScopes_RemovedScope_TornDownAndClearedFromBookkeeping pins
// the removal path.
func TestHotReloadScopes_RemovedScope_TornDownAndClearedFromBookkeeping(t *testing.T) {
	dir := t.TempDir()
	a := New(config.RoleCore1, "test-node", 1, "psk", dir, testScopes("office"), nil)

	// Seed bookkeeping as if "office" were actually being served —
	// exactly the live state a hot-reload must safely unwind.
	a.mu.Lock()
	a.ready["office"] = time.Now()
	a.serving["office"] = true
	a.antiFlap["office"] = &AntiFlap{StableSince: time.Now(), Delay: time.Second}
	a.vrrpPriority["office"] = 100
	a.mu.Unlock()

	report := a.HotReloadScopes(map[string]config.ScopeConfig{})

	if len(report) != 1 || !strings.Contains(report[0], "office: removed") {
		t.Errorf("report = %v, want a single 'office: removed' line", report)
	}
	if _, ok := a.scopeConfig("office"); ok {
		t.Error("office still present in a.scopes after removal")
	}
	a.mu.Lock()
	_, ready := a.ready["office"]
	_, serving := a.serving["office"]
	_, antiFlap := a.antiFlap["office"]
	_, vrrp := a.vrrpPriority["office"]
	a.mu.Unlock()
	if ready || serving || antiFlap || vrrp {
		t.Errorf("stale bookkeeping survived removal: ready=%v serving=%v antiFlap=%v vrrp=%v",
			ready, serving, antiFlap, vrrp)
	}

	known := loadKnownScopes(dir)
	if _, ok := known["office"]; ok {
		t.Error("removed scope still present in persisted known-scopes.json")
	}
}

func TestHotReloadScopes_PhysicalFieldChange_DemotesFromReady(t *testing.T) {
	dir := t.TempDir()
	a := New(config.RoleCore1, "test-node", 1, "psk", dir, testScopes("office"), nil)
	a.mu.Lock()
	a.ready["office"] = time.Now()
	a.serving["office"] = true
	a.mu.Unlock()

	updated := testScopes("office")
	sc := updated["office"]
	sc.VLANID = 101
	updated["office"] = sc

	report := a.HotReloadScopes(updated)

	if len(report) != 1 || !strings.Contains(report[0], "physical definition changed") {
		t.Errorf("report = %v, want a single 'physical definition changed' line", report)
	}
	got, ok := a.scopeConfig("office")
	if !ok || got.VLANID != 101 {
		t.Errorf("scopeConfig(office) = %+v, ok=%v, want the NEW VLANID 101 visible immediately", got, ok)
	}
	a.mu.Lock()
	_, ready := a.ready["office"]
	_, serving := a.serving["office"]
	a.mu.Unlock()
	if ready {
		t.Error("office must be demoted from a.ready so Reconcile rebuilds its interface under the new VLAN")
	}
	if serving {
		t.Error("office must be cleared from a.serving too, or Reconcile would wrongly take the already-serving branch once reconstructed")
	}
}

// TestHotReloadScopes_NonPhysicalFieldChange_StaysReady is the other half:
// a DHCP-range-only edit must NOT touch a.ready/a.serving at all.
func TestHotReloadScopes_NonPhysicalFieldChange_StaysReady(t *testing.T) {
	dir := t.TempDir()
	a := New(config.RoleCore1, "test-node", 1, "psk", dir, testScopes("office"), nil)
	a.mu.Lock()
	a.ready["office"] = time.Now()
	a.serving["office"] = true
	a.mu.Unlock()

	updated := testScopes("office")
	sc := updated["office"]
	sc.DHCPRange = [2]string{"192.168.100.150", "192.168.100.250"}
	updated["office"] = sc

	report := a.HotReloadScopes(updated)

	if len(report) != 1 || !strings.Contains(report[0], "no interface rebuild needed") {
		t.Errorf("report = %v, want a single 'no interface rebuild needed' line", report)
	}
	got, ok := a.scopeConfig("office")
	if !ok || got.DHCPRange[0] != "192.168.100.150" {
		t.Errorf("scopeConfig(office) = %+v, ok=%v, want the new DHCP range visible immediately", got, ok)
	}
	a.mu.Lock()
	_, ready := a.ready["office"]
	_, serving := a.serving["office"]
	a.mu.Unlock()
	if !ready || !serving {
		t.Error("a non-physical field change must never disturb a.ready/a.serving — the scope keeps serving uninterrupted")
	}
}

func TestHotReloadScopes_NodeIPChangeIsTreatedAsPhysical(t *testing.T) {
	dir := t.TempDir()
	a := New(config.RoleCore1, "test-node", 1, "psk", dir, testScopes("office"), nil)
	a.mu.Lock()
	a.ready["office"] = time.Now()
	a.mu.Unlock()

	updated := testScopes("office")
	sc := updated["office"]
	sc.NodeIP = "192.168.100.23/24" // was .22
	updated["office"] = sc

	a.HotReloadScopes(updated)

	a.mu.Lock()
	_, ready := a.ready["office"]
	a.mu.Unlock()
	if ready {
		t.Error("a NodeIP-only change must still demote the scope from a.ready — it's a physical interface-address change")
	}
}

func TestHotReloadScopes_NoChanges_EmptyReport(t *testing.T) {
	dir := t.TempDir()
	scopes := testScopes("office")
	a := New(config.RoleCore1, "test-node", 1, "psk", dir, scopes, nil)

	report := a.HotReloadScopes(testScopes("office"))
	if len(report) != 0 {
		t.Errorf("report = %v, want empty — nothing actually changed", report)
	}
}

func TestPublishScopes_DefensiveCopy(t *testing.T) {
	dir := t.TempDir()
	a := New(config.RoleCore1, "test-node", 1, "psk", dir, nil, nil)

	m := map[string]config.ScopeConfig{"office": {VLANID: 100}}
	a.publishScopes(m)
	m["office"] = config.ScopeConfig{VLANID: 999} // mutate the caller's own map afterward

	got, _ := a.scopeConfig("office")
	if got.VLANID != 100 {
		t.Errorf("VLANID = %d, want 100 — a.scopes must not alias the caller's map", got.VLANID)
	}
}

func TestVRRPConfigSignature_DetectsRelevantFieldChanges(t *testing.T) {
	base := map[string]config.ScopeConfig{
		"office": {VIP: "10.0.0.1/24", VRRPID: 50, AdvertIntMS: 1000, VRRPVersion: 2},
	}
	same := map[string]config.ScopeConfig{
		"office": {VIP: "10.0.0.1/24", VRRPID: 50, AdvertIntMS: 1000, VRRPVersion: 2},
	}
	if vrrpConfigSignature(base) != vrrpConfigSignature(same) {
		t.Error("identical VRRP-relevant fields produced different signatures")
	}

	for _, mutate := range []func(config.ScopeConfig) config.ScopeConfig{
		func(sc config.ScopeConfig) config.ScopeConfig { sc.VIP = "10.0.0.2/24"; return sc },
		func(sc config.ScopeConfig) config.ScopeConfig { sc.VRRPID = 51; return sc },
		func(sc config.ScopeConfig) config.ScopeConfig { sc.AdvertIntMS = 500; return sc },
		func(sc config.ScopeConfig) config.ScopeConfig { sc.VRRPVersion = 3; return sc },
	} {
		changed := map[string]config.ScopeConfig{"office": mutate(base["office"])}
		if vrrpConfigSignature(base) == vrrpConfigSignature(changed) {
			t.Errorf("signature unchanged after mutating a VRRP-relevant field: %+v", changed["office"])
		}
	}
}

// TestVRRPConfigSignature_IgnoresUnrelatedFields confirms the signature
// stays stable for fields renderKeepalivedConfigAll never reads (e.g.
// DHCPRange).
func TestVRRPConfigSignature_IgnoresUnrelatedFields(t *testing.T) {
	base := map[string]config.ScopeConfig{
		"office": {VIP: "10.0.0.1/24", VRRPID: 50, DHCPRange: [2]string{"10.0.0.100", "10.0.0.200"}},
	}
	changed := map[string]config.ScopeConfig{
		"office": {VIP: "10.0.0.1/24", VRRPID: 50, DHCPRange: [2]string{"10.0.0.150", "10.0.0.250"}},
	}
	if vrrpConfigSignature(base) != vrrpConfigSignature(changed) {
		t.Error("signature changed for a DHCPRange-only edit — must be VRRP-fields-only")
	}
}
