// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"os"
	"path/filepath"
	"testing"

	"dnshived/internal/config"
)

func TestRemovedScopes_FindsOnlyNamesMissingFromCurrent(t *testing.T) {
	known := map[string]knownScope{
		"office":   {Parent: "ens19", VLANID: 100},
		"av-dante": {Parent: "ens19", VLANID: 101},
	}
	current := map[string]config.ScopeConfig{
		"office": {Parent: "ens19", VLANID: 100},
	}

	got := removedScopes(known, current)
	if len(got) != 1 || got[0] != "av-dante" {
		t.Fatalf("removedScopes = %v, want [av-dante]", got)
	}
}

func TestRemovedScopes_NothingRemovedWhenSetsMatch(t *testing.T) {
	known := map[string]knownScope{"office": {Parent: "ens19", VLANID: 100}}
	current := map[string]config.ScopeConfig{"office": {Parent: "ens19", VLANID: 100}}

	if got := removedScopes(known, current); len(got) != 0 {
		t.Errorf("removedScopes = %v, want none", got)
	}
}

func TestRemovedScopes_InPlaceVLANChangeIsDetected(t *testing.T) {
	known := map[string]knownScope{"rw-100": {Parent: "ens19", VLANID: 100}}
	current := map[string]config.ScopeConfig{"rw-100": {Parent: "ens19", VLANID: 237}}

	got := removedScopes(known, current)
	if len(got) != 1 || got[0] != "rw-100" {
		t.Fatalf("removedScopes = %v, want [rw-100] — the OLD vlan_id 100 infrastructure must be torn down even though the scope name is still configured", got)
	}
}

// TestRemovedScopes_InPlaceParentChangeIsDetected covers the other half of
// the same tuple.
func TestRemovedScopes_InPlaceParentChangeIsDetected(t *testing.T) {
	known := map[string]knownScope{"rw-100": {Parent: "ens19", VLANID: 100}}
	current := map[string]config.ScopeConfig{"rw-100": {Parent: "ens20", VLANID: 100}}

	got := removedScopes(known, current)
	if len(got) != 1 || got[0] != "rw-100" {
		t.Fatalf("removedScopes = %v, want [rw-100] — a parent-interface change must also trigger teardown of the old interface", got)
	}
}

func TestRemovedScopes_EmptyCurrentRemovesEverythingKnown(t *testing.T) {
	known := map[string]knownScope{
		"rw-100": {Parent: "ens19", VLANID: 100},
		"rw-101": {Parent: "ens19", VLANID: 101},
	}
	got := removedScopes(known, map[string]config.ScopeConfig{})
	if len(got) != 2 {
		t.Fatalf("removedScopes = %v, want 2 entries", got)
	}
}

func TestKnownScopes_SaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	scopes := map[string]config.ScopeConfig{
		"office": {Parent: "ens19", VLANID: 100},
	}
	if err := saveKnownScopes(dir, scopes); err != nil {
		t.Fatalf("saveKnownScopes: %v", err)
	}

	got := loadKnownScopes(dir)
	if len(got) != 1 || got["office"].Parent != "ens19" || got["office"].VLANID != 100 {
		t.Fatalf("loadKnownScopes = %+v, want office/ens19/100", got)
	}
}

func TestLoadKnownScopes_MissingFileReturnsNil(t *testing.T) {
	if got := loadKnownScopes(t.TempDir()); got != nil {
		t.Errorf("loadKnownScopes = %v, want nil for a missing file", got)
	}
}

func TestLoadKnownScopes_CorruptFileReturnsNilNotError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(knownScopesPath(dir), []byte("not json"), 0o640); err != nil {
		t.Fatal(err)
	}
	if got := loadKnownScopes(dir); got != nil {
		t.Errorf("loadKnownScopes = %v, want nil for a corrupt file", got)
	}
}

func TestDecommissionRemovedScopes_ArbiterRoleTearsDownToo(t *testing.T) {
	dir := t.TempDir()
	if err := saveKnownScopes(dir, testScopes("stale-scope")); err != nil {
		t.Fatal(err)
	}
	current := testScopes("office")
	a := New(config.RoleCore3, "test-node", 1, "psk", dir, current, nil)

	removed, err := a.DecommissionRemovedScopes()
	if err != nil {
		t.Fatalf("DecommissionRemovedScopes error = %v, want nil", err)
	}
	if len(removed) != 1 || removed[0] != "stale-scope" {
		t.Fatalf("DecommissionRemovedScopes = %v, want [stale-scope] (arbiter must decommission too)", removed)
	}
	got := loadKnownScopes(dir)
	if _, ok := got["stale-scope"]; ok {
		t.Error("stale-scope is still in the persisted known-scopes set after decommissioning")
	}
	if _, ok := got["office"]; !ok {
		t.Error("office (still configured) should be in the persisted known-scopes set")
	}
}

func TestDecommissionRemovedScopes_TearsDownAndPrunesRemovedScope(t *testing.T) {
	dir := t.TempDir()
	prior := testScopes("stale-scope") // ens19.100
	if err := saveKnownScopes(dir, prior); err != nil {
		t.Fatal(err)
	}
	dnsmasqConf := filepath.Join(dir, "dnsmasq-stale-scope.conf")
	reservationsConf := filepath.Join(dir, "reservations-stale-scope.conf")
	leasesFile := filepath.Join(dir, "leases-stale-scope")
	os.WriteFile(dnsmasqConf, []byte("stale"), 0o640)
	os.WriteFile(reservationsConf, []byte("stale"), 0o640)
	os.WriteFile(leasesFile, []byte("stale"), 0o640)

	// Current config no longer has stale-scope, but does have a different
	// scope — confirms decommission only touches what's actually gone.
	current := testScopes("office")
	a := New(config.RoleCore1, "test-node", 1, "psk", dir, current, nil)

	removed, err := a.DecommissionRemovedScopes()
	if err != nil {
		t.Fatalf("DecommissionRemovedScopes error = %v, want nil", err)
	}
	if len(removed) != 1 || removed[0] != "stale-scope" {
		t.Fatalf("DecommissionRemovedScopes = %v, want [stale-scope]", removed)
	}

	if _, err := os.Stat(dnsmasqConf); !os.IsNotExist(err) {
		t.Error("dnsmasq render artifact for the removed scope was not cleaned up")
	}
	if _, err := os.Stat(reservationsConf); !os.IsNotExist(err) {
		t.Error("reservations render artifact for the removed scope was not cleaned up")
	}
	if _, err := os.Stat(leasesFile); !os.IsNotExist(err) {
		t.Error("dnsmasq lease file for the removed scope was not cleaned up")
	}

	got := loadKnownScopes(dir)
	if _, ok := got["stale-scope"]; ok {
		t.Error("stale-scope is still in the persisted known-scopes set after decommissioning")
	}
	if _, ok := got["office"]; !ok {
		t.Error("office (still configured) should be in the persisted known-scopes set")
	}
}

// TestDecommissionRemovedScopes_InPlaceVLANChangeTearsDownOldInterface is
// the end-to-end version of TestRemovedScopes_InPlaceVLANChangeIsDetected.
func TestDecommissionRemovedScopes_InPlaceVLANChangeTearsDownOldInterface(t *testing.T) {
	dir := t.TempDir()
	prior := testScopes("rw-100") // ens19.100
	if err := saveKnownScopes(dir, prior); err != nil {
		t.Fatal(err)
	}

	current := testScopes("rw-100")
	moved := current["rw-100"]
	moved.VLANID = 237
	current["rw-100"] = moved
	a := New(config.RoleCore1, "test-node", 1, "psk", dir, current, nil)

	removed, err := a.DecommissionRemovedScopes()
	if err != nil {
		t.Fatalf("DecommissionRemovedScopes error = %v, want nil", err)
	}
	if len(removed) != 1 || removed[0] != "rw-100" {
		t.Fatalf("DecommissionRemovedScopes = %v, want [rw-100] — the old VLAN 100 infrastructure must be torn down", removed)
	}

	got := loadKnownScopes(dir)
	ks, ok := got["rw-100"]
	if !ok {
		t.Fatal("rw-100 must still be in the persisted known-scopes set — it's still configured, just on a new VLAN")
	}
	if ks.VLANID != 237 {
		t.Errorf("persisted VLANID = %d, want 237 (the new value)", ks.VLANID)
	}
}

func TestDecommissionRemovedScopes_NothingRemovedReturnsNilAndStillPersists(t *testing.T) {
	dir := t.TempDir()
	current := testScopes("office")
	if err := saveKnownScopes(dir, current); err != nil {
		t.Fatal(err)
	}
	a := New(config.RoleCore1, "test-node", 1, "psk", dir, current, nil)

	if got, err := a.DecommissionRemovedScopes(); got != nil || err != nil {
		t.Errorf("DecommissionRemovedScopes = %v, %v, want nil, nil when nothing changed", got, err)
	}
}

func TestIsUnsafeScopeName(t *testing.T) {
	unsafe := []string{"../../etc/cron.d/evil", "a/b", ".", ".."}
	for _, name := range unsafe {
		if !isUnsafeScopeName(name) {
			t.Errorf("isUnsafeScopeName(%q) = false, want true", name)
		}
	}
	safe := []string{"rw-100", "office", "av-dante"}
	for _, name := range safe {
		if isUnsafeScopeName(name) {
			t.Errorf("isUnsafeScopeName(%q) = true, want false", name)
		}
	}
}

func TestDecommissionRemovedScopes_SkipsPathTraversalNames(t *testing.T) {
	dir := t.TempDir()
	tampered := `{"../../etc/cron.d/evil": {"parent": "ens19", "vlan_id": 100}, "..": {"parent": "ens19", "vlan_id": 101}}`
	if err := os.WriteFile(knownScopesPath(dir), []byte(tampered), 0o640); err != nil {
		t.Fatal(err)
	}
	a := New(config.RoleCore1, "test-node", 1, "psk", dir, nil, nil)

	removed, err := a.DecommissionRemovedScopes()
	if err != nil {
		t.Fatalf("DecommissionRemovedScopes error = %v, want nil", err)
	}
	if len(removed) != 2 {
		t.Fatalf("removed = %v, want 2 entries", removed)
	}
}

func TestDecommissionRemovedScopes_FirstRunWithNoKnownScopesFileIsANoop(t *testing.T) {
	dir := t.TempDir()
	current := testScopes("office")
	a := New(config.RoleCore1, "test-node", 1, "psk", dir, current, nil)

	if got, err := a.DecommissionRemovedScopes(); got != nil || err != nil {
		t.Errorf("DecommissionRemovedScopes = %v, %v, want nil, nil on first run with no prior state", got, err)
	}
	// It should still start tracking from this point forward.
	got := loadKnownScopes(dir)
	if _, ok := got["office"]; !ok {
		t.Error("first run should seed the known-scopes file with the current config")
	}
}
