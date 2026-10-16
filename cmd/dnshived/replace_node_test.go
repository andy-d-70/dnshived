// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"dnshived/internal/cluster"
	"dnshived/internal/config"
	"dnshived/internal/identity"
	"dnshived/internal/reliability"
)

func TestFindSurvivingPeer_FindsThirdRoleOnly(t *testing.T) {
	snapshot := []cluster.PeerState{
		{Addr: "192.168.0.23:9443", Reachable: true, Identity: &identity.Identity{Role: "core-2"}},
		{Addr: "192.168.0.24:9443", Reachable: true, Identity: &identity.Identity{Role: "core-3"}},
	}
	addr, role, err := findSurvivingPeer(snapshot, "core-1", "core-2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr != "192.168.0.24:9443" || role != "core-3" {
		t.Errorf("findSurvivingPeer = (%q, %q), want (192.168.0.24:9443, arbiter)", addr, role)
	}
}

func TestResolveReplacementControlAddr_UsesReachHostWithConventionPort(t *testing.T) {
	got := resolveReplacementControlAddr("192.168.0.23:80", "192.168.0.22:9443")
	if got != "192.168.0.23:9443" {
		t.Errorf("resolveReplacementControlAddr = %q, want 192.168.0.23:9443", got)
	}
}

func TestResolveReplacementControlAddr_SameConventionPortIsANoOp(t *testing.T) {
	got := resolveReplacementControlAddr("192.168.0.23:9443", "192.168.0.22:9443")
	if got != "192.168.0.23:9443" {
		t.Errorf("resolveReplacementControlAddr = %q, want 192.168.0.23:9443 unchanged", got)
	}
}

func TestResolveReplacementControlAddr_BareHostGetsConventionPort(t *testing.T) {
	got := resolveReplacementControlAddr("192.168.0.23", "192.168.0.22:9443")
	if got != "192.168.0.23:9443" {
		t.Errorf("resolveReplacementControlAddr = %q, want 192.168.0.23:9443", got)
	}
}

func TestResolveReplacementControlAddr_MalformedInputFallsBackToReachAddr(t *testing.T) {
	if got := resolveReplacementControlAddr("2001:db8::1", "192.168.0.22:9443"); got != "2001:db8::1" {
		t.Errorf("resolveReplacementControlAddr = %q, want the malformed reachAddr returned unchanged", got)
	}
	if got := resolveReplacementControlAddr("192.168.0.23:80", "not-an-address"); got != "192.168.0.23:80" {
		t.Errorf("resolveReplacementControlAddr = %q, want reachAddr returned unchanged when conventionAddr is unparseable", got)
	}
}

func TestResolveOldDeadAddr_PrefersExplicitReqOldAddr(t *testing.T) {
	got := resolveOldDeadAddr("192.168.0.23:9443", "192.168.0.24:9443", []string{"192.168.0.24:9443", "192.168.0.99:9443"})
	if got != "192.168.0.23:9443" {
		t.Errorf("resolveOldDeadAddr = %q, want the explicit req.OldAddr, unchanged", got)
	}
}

func TestResolveOldDeadAddr_FallsBackToEliminationWhenReqOldAddrEmpty(t *testing.T) {
	got := resolveOldDeadAddr("", "192.168.0.24:9443", []string{"192.168.0.24:9443", "192.168.0.23:9443"})
	if got != "192.168.0.23:9443" {
		t.Errorf("resolveOldDeadAddr = %q, want 192.168.0.23:9443 (eliminated against thirdAddr)", got)
	}
}

func TestResolveOldDeadAddr_EmptyWhenThirdAddrUnknownAndNoExplicit(t *testing.T) {
	got := resolveOldDeadAddr("", "", []string{"192.168.0.43:9443"})
	if got != "" {
		t.Errorf("resolveOldDeadAddr = %q, want empty (no reliable way to identify the dead address)", got)
	}
}

func TestFindSurvivingPeer_ErrorsWhenNoneReachable(t *testing.T) {
	snapshot := []cluster.PeerState{
		{Addr: "192.168.0.23:9443", Reachable: false, Identity: &identity.Identity{Role: "core-2"}},
	}
	if _, _, err := findSurvivingPeer(snapshot, "core-1", "core-3"); err == nil {
		t.Fatal("expected an error when no reachable third peer exists, got nil")
	}
}

func TestUpdatePeerInConfig_ReplacesMatchingAddress(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")
	cc := &config.Cluster{
		SchemaVersion: 2, ClusterID: "c", NodeID: "worker-a-x", Role: "core-1",
		ControlAddr: "192.168.0.22:9443", DataDir: dir, PSK: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
		Peers:  []string{"192.168.0.23:9443-OLD", "192.168.0.24:9443"},
		Scopes: map[string]config.ScopeConfig{},
	}
	raw, _ := json.MarshalIndent(cc, "", "  ")
	if err := os.WriteFile(path, raw, 0o640); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	updated, err := updatePeerInConfig(path, "192.168.0.23:9443-OLD", "192.168.0.23:9443-NEW")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !updated {
		t.Fatal("updatePeerInConfig reported no update, want true")
	}

	reloaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error reloading: %v", err)
	}
	found := false
	for _, p := range reloaded.Peers {
		if p == "192.168.0.23:9443-NEW" {
			found = true
		}
		if p == "192.168.0.23:9443-OLD" {
			t.Error("old address still present in saved Peers")
		}
	}
	if !found {
		t.Error("new address not present in saved Peers")
	}
}

func TestRemapScopeNodeIPs_RecalculatesForNewOwnAddress(t *testing.T) {
	scopes := map[string]config.ScopeConfig{
		"rw-100": {NodeIP: "172.16.100.23/24", VLANID: 100},
		"rw-110": {NodeIP: "172.16.110.23/24", VLANID: 110},
	}
	got := remapScopeNodeIPs(scopes, "192.168.0.22:9443")

	if got["rw-100"].NodeIP != "172.16.100.22/24" {
		t.Errorf("rw-100 NodeIP = %q, want 172.16.100.22/24", got["rw-100"].NodeIP)
	}
	if got["rw-110"].NodeIP != "172.16.110.22/24" {
		t.Errorf("rw-110 NodeIP = %q, want 172.16.110.22/24", got["rw-110"].NodeIP)
	}
	// The subnet/prefix and every other field must stay untouched —
	// only the NodeIP's own last octet changes.
	if got["rw-100"].VLANID != 100 {
		t.Errorf("rw-100 VLANID = %d, want unchanged 100", got["rw-100"].VLANID)
	}
	// The original map must never be mutated — a shared reference back
	// to the survivor's own live config would be its own real hazard.
	if scopes["rw-100"].NodeIP != "172.16.100.23/24" {
		t.Error("remapScopeNodeIPs mutated its input map — the survivor's own config must stay untouched")
	}
}

func TestRemapScopeNodeIPs_LeavesUnparseableNodeIPUntouched(t *testing.T) {
	scopes := map[string]config.ScopeConfig{
		"weird": {NodeIP: "not-an-ip"},
		"empty": {NodeIP: ""},
	}
	got := remapScopeNodeIPs(scopes, "192.168.0.22:9443")
	if got["weird"].NodeIP != "not-an-ip" {
		t.Errorf("weird NodeIP = %q, want unchanged", got["weird"].NodeIP)
	}
	if got["empty"].NodeIP != "" {
		t.Errorf("empty NodeIP = %q, want unchanged empty", got["empty"].NodeIP)
	}
}

func TestResetNodeIPOverridesForRole_DropsOnlyTheGivenRole(t *testing.T) {
	scopes := map[string]config.ScopeConfig{
		"core3-test": {
			VLANID: 18,
			NodeIPOverrides: map[string]string{
				"core-1": "10.200.18.22/24",
				"core-2": "10.200.18.23/24",
				"core-3": "10.200.18.43/24", // stale — real core-3 is .24
			},
		},
		"no-override": {VLANID: 3},
	}
	got := resetNodeIPOverridesForRole(scopes, "core-3")

	overrides := got["core3-test"].NodeIPOverrides
	if _, stillPresent := overrides["core-3"]; stillPresent {
		t.Error("core-3's own override still present after reset")
	}
	if overrides["core-1"] != "10.200.18.22/24" || overrides["core-2"] != "10.200.18.23/24" {
		t.Errorf("other roles' overrides changed: %+v, want core-1/core-2 untouched", overrides)
	}
	if _, ok := got["no-override"]; !ok {
		t.Error("scope with no overrides at all disappeared from the result")
	}
	// Original input must never be mutated — the same defensive-copy
	// requirement remapScopeNodeIPs already established.
	if scopes["core3-test"].NodeIPOverrides["core-3"] != "10.200.18.43/24" {
		t.Error("resetNodeIPOverridesForRole mutated its input map")
	}
}

func TestResetNodeIPOverridesForRole_DropsMapEntirelyWhenEmptied(t *testing.T) {
	scopes := map[string]config.ScopeConfig{
		"solo": {NodeIPOverrides: map[string]string{"core-3": "10.0.0.43/24"}},
	}
	got := resetNodeIPOverridesForRole(scopes, "core-3")
	if got["solo"].NodeIPOverrides != nil {
		t.Errorf("NodeIPOverrides = %+v, want nil (not an empty map) once its last entry is reset", got["solo"].NodeIPOverrides)
	}
}

func TestResetRoleAddressing_ClearsBothScopesAndScopeDefaults(t *testing.T) {
	cfg := config.Cluster{
		Role: "core-1",
		ScopeDefaults: &config.ScopeDefaults{
			NodeIPSuffixes: map[string]string{"core-1": "22", "core-2": "23", "core-3": "43"},
		},
		Scopes: map[string]config.ScopeConfig{
			"s1": {NodeIPOverrides: map[string]string{"core-3": "10.0.0.43/24"}},
		},
	}
	got := resetRoleAddressing(cfg, "core-3", "")

	if _, ok := got.ScopeDefaults.NodeIPSuffixes["core-3"]; ok {
		t.Error("ScopeDefaults.NodeIPSuffixes still has core-3 after reset")
	}
	if got.ScopeDefaults.NodeIPSuffixes["core-1"] != "22" || got.ScopeDefaults.NodeIPSuffixes["core-2"] != "23" {
		t.Errorf("other roles' suffixes changed: %+v", got.ScopeDefaults.NodeIPSuffixes)
	}
	if _, ok := got.Scopes["s1"].NodeIPOverrides["core-3"]; ok {
		t.Error("scope s1's own core-3 override still present after reset")
	}
	if got.Role != "core-1" {
		t.Errorf("Role = %q, want unchanged core-1 — resetRoleAddressing must only touch addressing fields", got.Role)
	}
	if cfg.ScopeDefaults.NodeIPSuffixes["core-3"] != "43" {
		t.Error("resetRoleAddressing mutated the original cfg.ScopeDefaults in place")
	}
}

func TestResetRoleAddressing_NewAddrRecomputesSuffix(t *testing.T) {
	cfg := config.Cluster{
		Role: "core-1",
		ScopeDefaults: &config.ScopeDefaults{
			NodeIPSuffixes: map[string]string{"core-1": "22", "core-2": "23", "core-3": "99"},
		},
	}
	got := resetRoleAddressing(cfg, "core-3", "192.168.0.24:9443")
	if got.ScopeDefaults.NodeIPSuffixes["core-3"] != "24" {
		t.Errorf("NodeIPSuffixes[core-3] = %q, want 24 (recomputed from the new address)", got.ScopeDefaults.NodeIPSuffixes["core-3"])
	}
	if got.ScopeDefaults.NodeIPSuffixes["core-1"] != "22" || got.ScopeDefaults.NodeIPSuffixes["core-2"] != "23" {
		t.Errorf("other roles' suffixes changed: %+v", got.ScopeDefaults.NodeIPSuffixes)
	}
	// The original must never be mutated in place.
	if cfg.ScopeDefaults.NodeIPSuffixes["core-3"] != "99" {
		t.Error("resetRoleAddressing mutated the original cfg.ScopeDefaults in place")
	}
}

func TestResetRoleAddressing_NewAddrAddsSuffixWhenNoneExistedBefore(t *testing.T) {
	cfg := config.Cluster{Role: "core-1"}
	got := resetRoleAddressing(cfg, "core-3", "192.168.0.24:9443")
	if got.ScopeDefaults == nil || got.ScopeDefaults.NodeIPSuffixes["core-3"] != "24" {
		t.Fatalf("got.ScopeDefaults = %+v, want NodeIPSuffixes[core-3] = 24", got.ScopeDefaults)
	}
}

func TestResetRoleAddressing_UnparsableNewAddrFallsBackToClear(t *testing.T) {
	cfg := config.Cluster{
		Role:          "core-1",
		ScopeDefaults: &config.ScopeDefaults{NodeIPSuffixes: map[string]string{"core-3": "99"}},
	}
	got := resetRoleAddressing(cfg, "core-3", "not-a-real-address")
	if _, ok := got.ScopeDefaults.NodeIPSuffixes["core-3"]; ok {
		t.Error("an unparsable newAddr should clear the entry, not leave or set a garbage value")
	}
}

func TestResetRoleAddressing_NoOpWhenRoleHasNoStaleValues(t *testing.T) {
	cfg := config.Cluster{
		Role:          "core-1",
		ScopeDefaults: &config.ScopeDefaults{NodeIPSuffixes: map[string]string{"core-1": "22"}},
		Scopes:        map[string]config.ScopeConfig{"s1": {VLANID: 5}},
	}
	got := resetRoleAddressing(cfg, "core-3", "")
	if got.ScopeDefaults.NodeIPSuffixes["core-1"] != "22" {
		t.Error("unrelated role's suffix changed by a no-op reset")
	}
	if got.Scopes["s1"].VLANID != 5 {
		t.Error("unrelated scope field changed by a no-op reset")
	}
}

func TestResetRoleAddressing_NilScopeDefaultsIsSafe(t *testing.T) {
	cfg := config.Cluster{Role: "core-1", Scopes: map[string]config.ScopeConfig{}}
	got := resetRoleAddressing(cfg, "core-3", "") // must not panic on nil ScopeDefaults
	if got.ScopeDefaults != nil {
		t.Error("ScopeDefaults should stay nil when it was nil going in")
	}
}

func TestResetRoleAddressingInConfig_PersistsAndReloads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")
	cc := &config.Cluster{
		SchemaVersion: 2, ClusterID: "c", NodeID: "worker-a-x", Role: "core-1",
		ControlAddr: "192.168.0.22:9443", DataDir: dir, PSK: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
		ScopeDefaults: &config.ScopeDefaults{
			NodeIPSuffixes: map[string]string{"core-3": "43"},
		},
		Platform: &config.Platform{Mgmt: "eth0", Workers: []string{"ens19"}},
		Scopes: map[string]config.ScopeConfig{
			"s1": {
				Parent: "ens19", VLANID: 100, VIP: "192.168.100.1/24",
				DHCPRange: [2]string{"192.168.100.100", "192.168.100.200"},
				Gateway:   "192.168.100.1",
				VRRPID:    51, PreferredWorker: config.RoleCore1,
				NodeIPOverrides: map[string]string{"core-3": "10.0.0.43/24"},
			},
		},
	}
	raw, _ := json.MarshalIndent(cc, "", "  ")
	if err := os.WriteFile(path, raw, 0o640); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	fresh, err := resetRoleAddressingInConfig(path, "core-3", "", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := fresh.Scopes["s1"].NodeIPOverrides["core-3"]; ok {
		t.Error("returned fresh config still has the stale override")
	}

	reloaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error reloading: %v", err)
	}
	if _, ok := reloaded.Scopes["s1"].NodeIPOverrides["core-3"]; ok {
		t.Error("stale override still present after reloading from disk")
	}
	if _, ok := reloaded.ScopeDefaults.NodeIPSuffixes["core-3"]; ok {
		t.Error("stale suffix still present after reloading from disk")
	}
}

func TestClearStalePathReliability_ClearsEveryConfiguredTrunk(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	observer := cluster.NewObserver(self, "self-addr", nil, "")
	observer.RestorePathReliability(map[string]reliability.Entry{
		"core-3|ens19": {Score: 70, WasHealthy: false},
		"core-3|ens20": {Score: 70, WasHealthy: false},
	})
	if score, known := observer.PathScore("core-3", "ens19"); !known || score != 70 {
		t.Fatalf("setup failed: PathScore(core-3, ens19) = %d, known=%v, want 70/true", score, known)
	}

	cfg := &config.Cluster{Platform: &config.Platform{Workers: []string{"ens19", "ens20"}}}
	clearStalePathReliability(observer, cfg, "core-3")

	if _, known := observer.PathScore("core-3", "ens19"); known {
		t.Error("ens19 PathScore still known after clearStalePathReliability — want cleared")
	}
	if _, known := observer.PathScore("core-3", "ens20"); known {
		t.Error("ens20 PathScore still known after clearStalePathReliability — want cleared")
	}
}

func TestClearStalePathReliability_NilPlatformIsSafe(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: "core-1"}
	observer := cluster.NewObserver(self, "self-addr", nil, "")
	cfg := &config.Cluster{}
	clearStalePathReliability(observer, cfg, "core-3")
}

func TestUpdatePeerInConfig_MissingOldAddrStillAddsNewAddr(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")
	cc := &config.Cluster{
		SchemaVersion: 2, ClusterID: "c", NodeID: "worker-a-x", Role: "core-1",
		ControlAddr: "192.168.0.22:9443", DataDir: dir, PSK: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
		Peers:  []string{"192.168.0.23:9443"},
		Scopes: map[string]config.ScopeConfig{},
	}
	raw, _ := json.MarshalIndent(cc, "", "  ")
	os.WriteFile(path, raw, 0o640)

	updated, err := updatePeerInConfig(path, "192.168.0.24:9443", "192.168.0.24:9443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !updated {
		t.Fatal("a re-onboarded node whose old address was already removed was not added back")
	}
	reloaded, _ := config.Load(path)
	if want := []string{"192.168.0.23:9443", "192.168.0.24:9443"}; !slices.Equal(reloaded.Peers, want) {
		t.Errorf("Peers = %v, want %v", reloaded.Peers, want)
	}

	if updated, _ := updatePeerInConfig(path, "192.168.0.24:9443", "192.168.0.24:9443"); updated {
		t.Error("second identical call reported an update, want idempotent")
	}
	if updated, _ := updatePeerInConfig(path, "", "192.168.0.22:9443"); updated {
		t.Error("added this node's own ControlAddr as a peer")
	}
}

func TestUpdatePeerInConfig_ReplaceDoesNotDuplicate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")
	cc := &config.Cluster{
		SchemaVersion: 2, ClusterID: "c", NodeID: "worker-a-x", Role: "core-1",
		ControlAddr: "192.168.0.22:9443", DataDir: dir, PSK: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
		Peers:  []string{"192.168.0.23:9443", "192.168.0.30:9443"},
		Scopes: map[string]config.ScopeConfig{},
	}
	raw, _ := json.MarshalIndent(cc, "", "  ")
	os.WriteFile(path, raw, 0o640)

	if _, err := updatePeerInConfig(path, "192.168.0.23:9443", "192.168.0.30:9443"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	reloaded, _ := config.Load(path)
	if want := []string{"192.168.0.30:9443"}; !slices.Equal(reloaded.Peers, want) {
		t.Errorf("Peers = %v, want %v", reloaded.Peers, want)
	}
}

func TestUpdatePeerInConfig_EmptyOldAddrAppendsMissingAddress(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")
	cc := &config.Cluster{
		SchemaVersion: 2, ClusterID: "c", NodeID: "core-1-x", Role: "core-1",
		ControlAddr: "192.168.0.23:9443", DataDir: dir, PSK: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
		Peers:  []string{"192.168.0.22:9443"},
		Scopes: map[string]config.ScopeConfig{},
	}
	raw, _ := json.MarshalIndent(cc, "", "  ")
	if err := os.WriteFile(path, raw, 0o640); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	updated, err := updatePeerInConfig(path, "", "192.168.0.24:9443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !updated {
		t.Fatal("updatePeerInConfig reported no update, want true (a genuinely new peer address)")
	}
	reloaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error reloading: %v", err)
	}
	want := []string{"192.168.0.22:9443", "192.168.0.24:9443"}
	if len(reloaded.Peers) != len(want) {
		t.Fatalf("Peers = %v, want %v", reloaded.Peers, want)
	}
	for i, p := range want {
		if reloaded.Peers[i] != p {
			t.Errorf("Peers[%d] = %q, want %q (full: %v)", i, reloaded.Peers[i], p, reloaded.Peers)
		}
	}
}

func TestUpdatePeerInConfig_EmptyOldAddrAlreadyPresentIsNoop(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")
	cc := &config.Cluster{
		SchemaVersion: 2, ClusterID: "c", NodeID: "core-1-x", Role: "core-1",
		ControlAddr: "192.168.0.23:9443", DataDir: dir, PSK: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
		Peers:  []string{"192.168.0.22:9443", "192.168.0.24:9443"},
		Scopes: map[string]config.ScopeConfig{},
	}
	raw, _ := json.MarshalIndent(cc, "", "  ")
	if err := os.WriteFile(path, raw, 0o640); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	updated, err := updatePeerInConfig(path, "", "192.168.0.24:9443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updated {
		t.Error("updatePeerInConfig reported an update for an address that was already present")
	}
}

// TestRemovePeerInConfig_RemovesMatchingAddress is the pure-removal
// counterpart of TestUpdatePeerInConfig_ReplacesMatchingAddress.
func TestRemovePeerInConfig_RemovesMatchingAddress(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")
	cc := &config.Cluster{
		SchemaVersion: 2, ClusterID: "c", NodeID: "worker-a-x", Role: "core-1",
		ControlAddr: "192.168.0.22:9443", DataDir: dir, PSK: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
		Peers:  []string{"192.168.0.23:9443", "192.168.0.24:9443"},
		Scopes: map[string]config.ScopeConfig{},
	}
	raw, _ := json.MarshalIndent(cc, "", "  ")
	if err := os.WriteFile(path, raw, 0o640); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	updated, err := removePeerInConfig(path, "192.168.0.23:9443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !updated {
		t.Fatal("removePeerInConfig reported no update, want true")
	}

	reloaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error reloading: %v", err)
	}
	if len(reloaded.Peers) != 1 || reloaded.Peers[0] != "192.168.0.24:9443" {
		t.Errorf("reloaded.Peers = %v, want exactly [192.168.0.24:9443]", reloaded.Peers)
	}
}

func TestRemovePeerInConfig_NoMatchIsNoop(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")
	cc := &config.Cluster{
		SchemaVersion: 2, ClusterID: "c", NodeID: "worker-a-x", Role: "core-1",
		ControlAddr: "192.168.0.22:9443", DataDir: dir, PSK: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
		Peers:  []string{"192.168.0.23:9443", "192.168.0.24:9443"},
		Scopes: map[string]config.ScopeConfig{},
	}
	raw, _ := json.MarshalIndent(cc, "", "  ")
	os.WriteFile(path, raw, 0o640)

	updated, err := removePeerInConfig(path, "10.0.0.1:9999")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updated {
		t.Error("removePeerInConfig reported an update for an address that was never present")
	}
}

func TestRemovePeerHandler_RemovesFromConfigAndLiveObserver(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")
	cc := &config.Cluster{
		SchemaVersion: 2, ClusterID: "c", NodeID: "worker-a-x", Role: "core-1",
		ControlAddr: "192.168.0.22:9443", DataDir: dir, PSK: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
		Peers:  []string{"192.168.0.43:9443"},
		Scopes: map[string]config.ScopeConfig{},
	}
	raw, _ := json.MarshalIndent(cc, "", "  ")
	if err := os.WriteFile(path, raw, 0o640); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	self := identity.Identity{Role: "core-1"}
	observer := cluster.NewObserver(self, "192.168.0.22:9443", []string{"192.168.0.43:9443"}, "")

	body, _ := json.Marshal(removePeerRequest{Addr: "192.168.0.43:9443"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/remove-peer", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	removePeerHandler(path, observer, nil, nil, nil)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	reloaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error reloading: %v", err)
	}
	for _, p := range reloaded.Peers {
		if p == "192.168.0.43:9443" {
			t.Error("removed address still present in saved Peers")
		}
	}

	found := false
	for _, ps := range observer.Snapshot() {
		if ps.Addr == "192.168.0.43:9443" {
			found = true
		}
	}
	if found {
		t.Error("removed address still present in the live Observer's own peer set — RemovePeer wasn't actually called")
	}
}

// TestReplaceNodeHandler_RejectsSelfRoleAndMissingFields covers the
// request-validation path.
func TestReplaceNodeHandler_RejectsSelfRoleAndMissingFields(t *testing.T) {
	origCfg := currentConfig.Load()
	t.Cleanup(func() { currentConfig.Store(origCfg) })
	currentConfig.Store(&config.Cluster{Role: "core-1", ControlAddr: "192.168.0.22:9443"})

	self := identity.Identity{Role: "core-1"}
	observer := cluster.NewObserver(self, "192.168.0.22:9443", nil, "")
	handler := replaceNodeHandler(t.TempDir()+"/cluster.json", observer, nil, nil, nil)

	for _, req := range []replaceNodeRequest{
		{Role: "core-1", Addr: "1.2.3.4:9443", OTP: "x"},     // self role
		{Role: "core-2", Addr: "", OTP: "x"},                 // missing addr
		{Role: "not-a-role", Addr: "1.2.3.4:9443", OTP: "x"}, // invalid role
	} {
		body, _ := json.Marshal(req)
		httpReq := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/replace", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		handler(rec, httpReq)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("req %+v: status = %d, want 400: %s", req, rec.Code, rec.Body.String())
		}
	}
}

func TestRemovePeerHandler_DropsTrustedHostAndForwardsToRemainingPeers(t *testing.T) {
	got := make(chan removePeerRequest, 1)
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/nodes/remove-peer" || r.Header.Get("Authorization") != "Bearer admintok" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var req removePeerRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		got <- req
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true, "updated": false})
	}))
	defer other.Close()
	otherAddr := other.Listener.Addr().String()

	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")
	cc := &config.Cluster{
		SchemaVersion: 2, ClusterID: "c", NodeID: "core-1-x", Role: "core-1",
		ControlAddr: "192.168.0.51:9443", DataDir: dir, PSK: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
		Peers:        []string{"192.168.0.52:9443", otherAddr},
		TrustedHosts: []string{"192.168.0.51", "192.168.0.52", "127.0.0.1"},
		APITokens:    []config.APIToken{{Name: "a", Token: "admintok", Role: "admin"}},
		Scopes:       map[string]config.ScopeConfig{},
	}
	raw, _ := json.MarshalIndent(cc, "", "  ")
	if err := os.WriteFile(path, raw, 0o640); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	observer := cluster.NewObserver(identity.Identity{Role: "core-1"}, "192.168.0.51:9443", cc.Peers, "")

	body, _ := json.Marshal(removePeerRequest{Addr: "192.168.0.52:9443", Role: "core-2"})
	rec := httptest.NewRecorder()
	removePeerHandler(path, observer, nil, nil, nil)(rec, httptest.NewRequest(http.MethodPost, "/api/v1/nodes/remove-peer", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	reloaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("unexpected error reloading: %v", err)
	}
	for _, h := range reloaded.TrustedHosts {
		if h == "192.168.0.52" {
			t.Error("departed host still in saved TrustedHosts")
		}
	}

	select {
	case fwd := <-got:
		if fwd.Addr != "192.168.0.52:9443" || fwd.Role != "core-2" {
			t.Errorf("forwarded request = %+v, want the departed addr and role", fwd)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("removal was never forwarded to the remaining peer")
	}
}

func TestRemovePeerHandler_AlreadyRemovedDoesNotForward(t *testing.T) {
	called := make(chan struct{}, 1)
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called <- struct{}{}
	}))
	defer other.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")
	cc := &config.Cluster{
		SchemaVersion: 2, ClusterID: "c", NodeID: "core-1-x", Role: "core-1",
		ControlAddr: "192.168.0.51:9443", DataDir: dir, PSK: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
		Peers:     []string{other.Listener.Addr().String()},
		APITokens: []config.APIToken{{Name: "a", Token: "admintok", Role: "admin"}},
		Scopes:    map[string]config.ScopeConfig{},
	}
	raw, _ := json.MarshalIndent(cc, "", "  ")
	if err := os.WriteFile(path, raw, 0o640); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	observer := cluster.NewObserver(identity.Identity{Role: "core-1"}, "192.168.0.51:9443", cc.Peers, "")

	body, _ := json.Marshal(removePeerRequest{Addr: "192.168.0.52:9443"})
	rec := httptest.NewRecorder()
	removePeerHandler(path, observer, nil, nil, nil)(rec, httptest.NewRequest(http.MethodPost, "/api/v1/nodes/remove-peer", bytes.NewReader(body)))

	select {
	case <-called:
		t.Error("forwarded a removal that changed nothing locally; this is what stops forwarding loops")
	case <-time.After(300 * time.Millisecond):
	}
}

func TestConfiguredThirdAddr(t *testing.T) {
	self := "192.168.0.51:9443"
	tests := []struct {
		name    string
		peers   []string
		oldDead string
		newAddr string
		want    string
	}{
		{"third member configured but down, replaced role's old address known", []string{"192.168.0.52:9443", "192.168.0.53:9443"}, "192.168.0.52:9443", "192.168.0.62:9443", "192.168.0.53:9443"},
		{"replaced role already removed from peers by decommission", []string{"192.168.0.53:9443"}, "", "192.168.0.52:9443", "192.168.0.53:9443"},
		{"same-node restore, new equals old", []string{"192.168.0.52:9443", "192.168.0.53:9443"}, "192.168.0.52:9443", "192.168.0.52:9443", "192.168.0.53:9443"},
		{"true sole survivor", nil, "", "192.168.0.52:9443", ""},
		{"old address unknown and two candidates: refuse to guess", []string{"192.168.0.52:9443", "192.168.0.53:9443"}, "", "192.168.0.62:9443", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := configuredThirdAddr(self, tt.peers, tt.oldDead, tt.newAddr); got != tt.want {
				t.Errorf("configuredThirdAddr = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestComputeTrustedHosts_KeepsConfiguredButDownThirdMember(t *testing.T) {
	third := configuredThirdAddr("192.168.0.51:9443", []string{"192.168.0.53:9443"}, "", "192.168.0.52:9443")
	got := computeTrustedHosts("192.168.0.51:9443", third, "192.168.0.52:9443")
	want := []string{"192.168.0.51", "192.168.0.52", "192.168.0.53"}
	if !slices.Equal(got, want) {
		t.Errorf("trusted_hosts = %v, want %v — a configured member that is down must stay trusted", got, want)
	}
}

func TestUpdatePeerHandler_AppliesPeerLiveWithoutRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")
	cc := &config.Cluster{
		SchemaVersion: 2, ClusterID: "c", NodeID: "core-1-x", Role: "core-1",
		ControlAddr: "192.168.0.51:9443", DataDir: dir, PSK: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
		Peers:  []string{"192.168.0.52:9443"},
		Scopes: map[string]config.ScopeConfig{},
	}
	raw, _ := json.MarshalIndent(cc, "", "  ")
	if err := os.WriteFile(path, raw, 0o640); err != nil {
		t.Fatal(err)
	}
	origCfg := currentConfig.Load()
	t.Cleanup(func() { currentConfig.Store(origCfg) })
	currentConfig.Store(cc)

	self := identity.Identity{ClusterID: "c", NodeID: "core-1-x", Role: "core-1"}
	observer := cluster.NewObserver(self, cc.ControlAddr, cc.Peers, cc.PSK)

	body, _ := json.Marshal(updatePeerRequest{NewAddr: "192.168.0.53:9443"})
	rec := httptest.NewRecorder()
	updatePeerHandler(path, observer, nil)(rec, httptest.NewRequest(http.MethodPost, "/api/v1/nodes/update-peer", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var known []string
	for _, ps := range observer.Snapshot() {
		known = append(known, ps.Addr)
	}
	if !slices.Contains(known, "192.168.0.53:9443") || !slices.Contains(known, "192.168.0.52:9443") {
		t.Errorf("observer peers = %v, want the existing peer plus the new one, added live", known)
	}
	if !slices.Contains(currentConfig.Load().Peers, "192.168.0.53:9443") {
		t.Errorf("currentConfig peers = %v, want the new peer", currentConfig.Load().Peers)
	}
	if observer.BelievedDown("192.168.0.53:9443") {
		t.Error("a just-added peer must not be reported as believed down before its first probe")
	}
}
