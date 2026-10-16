// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"testing"

	"dnshived/internal/config"
)

// obs is a small test helper building the map checkConfigSanity takes.
func obs(iface, scope string, ifIndex int) map[string]sanityIfaceObservation {
	return map[string]sanityIfaceObservation{iface: {scope: scope, ifIndex: ifIndex}}
}

func TestCheckConfigSanity_DisabledReturnsNil(t *testing.T) {
	a := New(config.RoleCore1, "test-node", 1, "psk", "/tmp", nil, nil)
	a.SetSanityCheckDisabled(true)

	found := a.checkConfigSanity(obs("ens19.42", "office", 42))
	if found != nil {
		t.Errorf("found = %v, want nil when disabled", found)
	}
	if len(a.lastIfaceIndex) != 0 {
		t.Errorf("lastIfaceIndex = %v, want untouched (empty) when disabled", a.lastIfaceIndex)
	}
}

func TestCheckConfigSanity_EmptyInputReturnsNil(t *testing.T) {
	a := New(config.RoleCore1, "test-node", 1, "psk", "/tmp", nil, nil)

	if found := a.checkConfigSanity(map[string]sanityIfaceObservation{}); found != nil {
		t.Errorf("found = %v, want nil for zero ready scopes", found)
	}
}

func TestCheckConfigSanity_FirstObservation_CachesWithoutAFinding(t *testing.T) {
	a := New(config.RoleCore1, "test-node", 1, "psk", "/tmp", nil, nil)

	found := a.checkConfigSanity(obs("ens19.42", "office", 42))
	if len(found) != 0 {
		t.Errorf("found = %v, want none on an interface's first-ever observation", found)
	}
	if got := a.lastIfaceIndex["ens19.42"]; got != 42 {
		t.Errorf("lastIfaceIndex[ens19.42] = %d, want 42 (cached from this first observation)", got)
	}
}

func TestCheckConfigSanity_MatchingIndex_NoFinding(t *testing.T) {
	a := New(config.RoleCore1, "test-node", 1, "psk", "/tmp", nil, nil)
	a.lastIfaceIndex = map[string]int{"ens19.42": 42}

	found := a.checkConfigSanity(obs("ens19.42", "office", 42))
	if len(found) != 0 {
		t.Errorf("found = %v, want none when planned == running", found)
	}
	if got := a.lastIfaceIndex["ens19.42"]; got != 42 {
		t.Errorf("lastIfaceIndex[ens19.42] = %d, want unchanged 42", got)
	}
}

func TestCheckConfigSanity_DriftedIndex_ProducesFindingAndUpdatesCache(t *testing.T) {
	a := New(config.RoleCore1, "test-node", 1, "psk", "/tmp", nil, nil)
	a.lastIfaceIndex = map[string]int{"ens19.42": 42}

	found := a.checkConfigSanity(obs("ens19.42", "office", 99))
	if len(found) != 1 {
		t.Fatalf("found = %v, want exactly 1 finding for a genuine ifindex change", found)
	}
	f := found[0]
	if f.Scope != "office" || f.What != "relay_socket_stale" {
		t.Errorf("finding = %+v, want Scope=office What=relay_socket_stale", f)
	}
	if got := a.lastIfaceIndex["ens19.42"]; got != 99 {
		t.Errorf("lastIfaceIndex[ens19.42] = %d, want updated to 99 after detecting+healing the drift", got)
	}
}

func TestCheckConfigSanity_RenamedScope_SameInterfaceStillDetected(t *testing.T) {
	a := New(config.RoleCore1, "test-node", 1, "psk", "/tmp", nil, nil)
	// Tick 1: scope "test43" on ens19.43, ifindex 69, first observation.
	if found := a.checkConfigSanity(obs("ens19.43", "test43", 69)); len(found) != 0 {
		t.Fatalf("tick 1: found = %v, want none (first observation)", found)
	}
	found := a.checkConfigSanity(obs("ens19.43", "test43-check", 71))
	if len(found) != 1 {
		t.Fatalf("tick 2 (post-rename): found = %v, want exactly 1 finding — a scope rename must not hide a real ifindex change on its own unchanged physical interface", found)
	}
	if found[0].Scope != "test43-check" {
		t.Errorf("finding.Scope = %q, want the CURRENT (renamed) scope name test43-check", found[0].Scope)
	}
	if got := a.lastIfaceIndex["ens19.43"]; got != 71 {
		t.Errorf("lastIfaceIndex[ens19.43] = %d, want updated to 71", got)
	}
}

func TestCheckConfigSanity_ZeroRunningIndex_NeverAMismatch(t *testing.T) {
	a := New(config.RoleCore1, "test-node", 1, "psk", "/tmp", nil, nil)
	a.lastIfaceIndex = map[string]int{"ens19.42": 42}

	found := a.checkConfigSanity(obs("ens19.42", "office", 0))
	if len(found) != 0 {
		t.Errorf("found = %v, want none for a transiently-unresolvable interface (ifindex 0)", found)
	}
	if got := a.lastIfaceIndex["ens19.42"]; got != 42 {
		t.Errorf("lastIfaceIndex[ens19.42] = %d, want untouched 42 — nothing was actually confirmed", got)
	}
}

func TestCheckConfigSanity_OnlyDriftedInterfaceReported(t *testing.T) {
	a := New(config.RoleCore1, "test-node", 1, "psk", "/tmp", nil, nil)
	a.lastIfaceIndex = map[string]int{"ens19.42": 42, "ens20.50": 7}

	found := a.checkConfigSanity(map[string]sanityIfaceObservation{
		"ens19.42": {scope: "office", ifIndex: 42},
		"ens20.50": {scope: "av-dante", ifIndex: 70},
	})
	if len(found) != 1 || found[0].Scope != "av-dante" {
		t.Fatalf("found = %v, want exactly 1 finding for av-dante only", found)
	}
	if got := a.lastIfaceIndex["ens19.42"]; got != 42 {
		t.Errorf("lastIfaceIndex[ens19.42] = %d, want untouched 42 (this interface never drifted)", got)
	}
	if got := a.lastIfaceIndex["ens20.50"]; got != 70 {
		t.Errorf("lastIfaceIndex[ens20.50] = %d, want updated to 70", got)
	}
}

func TestSanityFingerprint_DeterministicRegardlessOfMapOrder(t *testing.T) {
	a := sanityFingerprint(map[string]int{"office": 1, "av-dante": 2, "rw-100": 3})
	b := sanityFingerprint(map[string]int{"rw-100": 3, "office": 1, "av-dante": 2})
	if a != b {
		t.Errorf("sanityFingerprint differs for the same content in different map iteration order: %q vs %q", a, b)
	}
}

func TestSanityFingerprint_DiffersOnRealContentChange(t *testing.T) {
	a := sanityFingerprint(map[string]int{"office": 1})
	b := sanityFingerprint(map[string]int{"office": 2})
	if a == b {
		t.Error("sanityFingerprint() identical for genuinely different content")
	}
}
