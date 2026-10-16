// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"testing"

	"dnshived/internal/cluster"
	"dnshived/internal/config"
	"dnshived/internal/identity"
)

func TestComputeFallbackTargets_OneAddrPerOtherRolePerParent(t *testing.T) {
	cfg := &config.Cluster{
		Role:        config.RoleCore1,
		ControlAddr: "192.168.0.22:9443",
		Scopes: map[string]config.ScopeConfig{
			"office": {
				Parent: "ens19",
				NodeIPOverrides: map[string]string{
					config.RoleCore2: "192.168.10.23/24",
					config.RoleCore3: "192.168.10.24/24",
				},
			},
		},
	}

	got := computeFallbackTargets(cfg, nil)
	want := map[string]map[string]string{
		config.RoleCore2: {"ens19": "192.168.10.23:9443"},
		config.RoleCore3: {"ens19": "192.168.10.24:9443"},
	}
	if len(got) != len(want) {
		t.Fatalf("computeFallbackTargets() = %v, want %v", got, want)
	}
	for role, byParent := range want {
		for parent, addr := range byParent {
			if got[role][parent] != addr {
				t.Errorf("computeFallbackTargets()[%q][%q] = %q, want %q", role, parent, got[role][parent], addr)
			}
		}
	}
	if _, ok := got[config.RoleCore1]; ok {
		t.Errorf("computeFallbackTargets() included this node's own role %q, want excluded", config.RoleCore1)
	}
}

func TestComputeFallbackTargets_MultipleParentsGetIndependentAddrs(t *testing.T) {
	cfg := &config.Cluster{
		Role:        config.RoleCore1,
		ControlAddr: "192.168.0.22:9443",
		Scopes: map[string]config.ScopeConfig{
			"office": {
				Parent:          "ens19",
				NodeIPOverrides: map[string]string{config.RoleCore2: "192.168.10.23/24"},
			},
			"dante": {
				Parent:          "ens20",
				NodeIPOverrides: map[string]string{config.RoleCore2: "192.168.20.23/24"},
			},
		},
	}
	got := computeFallbackTargets(cfg, nil)
	if len(got[config.RoleCore2]) != 2 {
		t.Fatalf("computeFallbackTargets()[core-2] = %v, want 2 independent parents", got[config.RoleCore2])
	}
	if got[config.RoleCore2]["ens19"] != "192.168.10.23:9443" {
		t.Errorf("computeFallbackTargets()[core-2][ens19] = %q, want 192.168.10.23:9443", got[config.RoleCore2]["ens19"])
	}
	if got[config.RoleCore2]["ens20"] != "192.168.20.23:9443" {
		t.Errorf("computeFallbackTargets()[core-2][ens20] = %q, want 192.168.20.23:9443", got[config.RoleCore2]["ens20"])
	}
}

func TestComputeFallbackTargets_NoScopesReturnsNil(t *testing.T) {
	cfg := &config.Cluster{
		Role:        config.RoleCore1,
		ControlAddr: "192.168.0.22:9443",
	}
	if got := computeFallbackTargets(cfg, nil); got != nil {
		t.Errorf("computeFallbackTargets() = %v, want nil", got)
	}
}

func TestComputeFallbackTargets_FirstScopeInSortedOrderWinsPerParent(t *testing.T) {
	cfg := &config.Cluster{
		Role:        config.RoleCore1,
		ControlAddr: "192.168.0.22:9443",
		Scopes: map[string]config.ScopeConfig{
			"zzz-scope": {Parent: "ens19", NodeIPOverrides: map[string]string{config.RoleCore2: "192.168.99.23/24"}},
			"aaa-scope": {Parent: "ens19", NodeIPOverrides: map[string]string{config.RoleCore2: "192.168.10.23/24"}},
		},
	}
	got := computeFallbackTargets(cfg, nil)
	want := "192.168.10.23:9443"
	if got[config.RoleCore2]["ens19"] != want {
		t.Errorf("computeFallbackTargets()[core-2][ens19] = %q, want %q (first scope in sorted order)", got[config.RoleCore2]["ens19"], want)
	}
}

// TestComputeFallbackTargets_MalformedControlAddrReturnsNil confirms a
// ControlAddr with no parseable port never panics or produces a garbage
// address.
func TestComputeFallbackTargets_MalformedControlAddrReturnsNil(t *testing.T) {
	cfg := &config.Cluster{
		Role:        config.RoleCore1,
		ControlAddr: "not-a-valid-addr",
		Scopes: map[string]config.ScopeConfig{
			"office": {Parent: "ens19", NodeIPOverrides: map[string]string{config.RoleCore2: "192.168.10.23/24"}},
		},
	}
	if got := computeFallbackTargets(cfg, nil); got != nil {
		t.Errorf("computeFallbackTargets() = %v, want nil (malformed ControlAddr)", got)
	}
}

func TestComputeFallbackTargets_DerivesFromNodeIPSuffixesWhenNoOverride(t *testing.T) {
	cfg := &config.Cluster{
		Role:        config.RoleCore1,
		ControlAddr: "192.168.0.23:9443",
		ScopeDefaults: &config.ScopeDefaults{
			NodeIPSuffixes: map[string]string{
				config.RoleCore1: "22",
				config.RoleCore2: "23",
				config.RoleCore3: "43",
			},
		},
		Scopes: map[string]config.ScopeConfig{
			"core3-test": {Parent: "ens19", VIP: "10.200.18.254/24"},
		},
	}
	got := computeFallbackTargets(cfg, nil)
	want := map[string]map[string]string{
		config.RoleCore2: {"ens19": "10.200.18.23:9443"},
		config.RoleCore3: {"ens19": "10.200.18.43:9443"},
	}
	if len(got) != len(want) {
		t.Fatalf("computeFallbackTargets() = %v, want %v", got, want)
	}
	for role, byParent := range want {
		for parent, addr := range byParent {
			if got[role][parent] != addr {
				t.Errorf("computeFallbackTargets()[%q][%q] = %q, want %q", role, parent, got[role][parent], addr)
			}
		}
	}
}

func TestFallbackAddrsTrustedHosts_AddsBareHostsFromFallbackMap(t *testing.T) {
	got := fallbackAddrsTrustedHosts(
		[]string{"192.168.0.22", "192.168.0.24"},
		map[string]map[string]string{
			"core-2": {"ens19": "10.200.18.23:9443"},
			"core-3": {"ens19": "10.200.18.43:9443"},
		},
	)
	want := map[string]bool{
		"192.168.0.22": true,
		"192.168.0.24": true,
		"10.200.18.23": true,
		"10.200.18.43": true,
	}
	if len(got) != len(want) {
		t.Fatalf("fallbackAddrsTrustedHosts() = %v, want exactly %v", got, want)
	}
	for _, h := range got {
		if !want[h] {
			t.Errorf("fallbackAddrsTrustedHosts() contains unexpected host %q", h)
		}
	}
}

// TestFallbackAddrsTrustedHosts_MultipleParentsAllTrusted confirms every
// trunk's own fallback host gets trusted, not just the first one found for
// a role.
func TestFallbackAddrsTrustedHosts_MultipleParentsAllTrusted(t *testing.T) {
	got := fallbackAddrsTrustedHosts(
		nil,
		map[string]map[string]string{
			"core-2": {"ens19": "192.168.10.23:9443", "ens20": "192.168.20.23:9443"},
		},
	)
	want := map[string]bool{"192.168.10.23": true, "192.168.20.23": true}
	if len(got) != len(want) {
		t.Fatalf("fallbackAddrsTrustedHosts() = %v, want exactly %v", got, want)
	}
	for _, h := range got {
		if !want[h] {
			t.Errorf("fallbackAddrsTrustedHosts() contains unexpected host %q", h)
		}
	}
}

func TestFallbackAddrsTrustedHosts_DedupesAgainstExisting(t *testing.T) {
	got := fallbackAddrsTrustedHosts(
		[]string{"10.200.18.23"},
		map[string]map[string]string{"core-2": {"ens19": "10.200.18.23:9443"}},
	)
	if len(got) != 1 || got[0] != "10.200.18.23" {
		t.Errorf("fallbackAddrsTrustedHosts() = %v, want exactly one deduped entry", got)
	}
}

func TestFallbackAddrsTrustedHosts_EmptyFallbackMapReturnsExistingUnchanged(t *testing.T) {
	existing := []string{"192.168.0.22", "192.168.0.24"}
	got := fallbackAddrsTrustedHosts(existing, nil)
	if len(got) != len(existing) {
		t.Errorf("fallbackAddrsTrustedHosts() = %v, want %v unchanged", got, existing)
	}
}

func TestComputeFallbackTargets_ExplicitOverrideWinsOverSuffixDerivation(t *testing.T) {
	cfg := &config.Cluster{
		Role:        config.RoleCore1,
		ControlAddr: "192.168.0.23:9443",
		ScopeDefaults: &config.ScopeDefaults{
			NodeIPSuffixes: map[string]string{config.RoleCore2: "23"},
		},
		Scopes: map[string]config.ScopeConfig{
			"office": {
				Parent:          "ens19",
				VIP:             "10.200.18.254/24",
				NodeIPOverrides: map[string]string{config.RoleCore2: "10.9.9.9/24"},
			},
		},
	}
	got := computeFallbackTargets(cfg, nil)
	want := "10.9.9.9:9443"
	if got[config.RoleCore2]["ens19"] != want {
		t.Errorf("computeFallbackTargets()[core-2][ens19] = %q, want %q (explicit override)", got[config.RoleCore2]["ens19"], want)
	}
}

func TestComputeFallbackTargets_ObserverDerivedWhenNoSuffixConfigured(t *testing.T) {
	cfg := &config.Cluster{
		Role:        config.RoleCore1,
		ControlAddr: "192.168.0.22:9443",
		Scopes: map[string]config.ScopeConfig{
			"office": {Parent: "ens19", VIP: "10.200.18.254/24"},
		},
	}
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: config.RoleCore1}
	observer := cluster.NewObserver(self, cfg.ControlAddr, nil, "")
	observer.SetPeerForTest("192.168.0.23:9443", &cluster.PeerState{
		Addr: "192.168.0.23:9443", Reachable: true,
		Identity: &identity.Identity{Role: config.RoleCore2},
	})

	got := computeFallbackTargets(cfg, observer)
	want := "10.200.18.23:9443"
	if got[config.RoleCore2]["ens19"] != want {
		t.Errorf("computeFallbackTargets()[core-2][ens19] = %q, want %q (derived from Observer, no suffix map configured)", got[config.RoleCore2]["ens19"], want)
	}
}

func TestComputeFallbackTargets_ObserverDerivedWinsOverStaticSuffix(t *testing.T) {
	cfg := &config.Cluster{
		Role:        config.RoleCore1,
		ControlAddr: "192.168.0.22:9443",
		ScopeDefaults: &config.ScopeDefaults{
			NodeIPSuffixes: map[string]string{config.RoleCore2: "99"},
		},
		Scopes: map[string]config.ScopeConfig{
			"office": {Parent: "ens19", VIP: "10.200.18.254/24"},
		},
	}
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: config.RoleCore1}
	observer := cluster.NewObserver(self, cfg.ControlAddr, nil, "")
	observer.SetPeerForTest("192.168.0.23:9443", &cluster.PeerState{
		Addr: "192.168.0.23:9443", Reachable: true,
		Identity: &identity.Identity{Role: config.RoleCore2},
	})

	got := computeFallbackTargets(cfg, observer)
	want := "10.200.18.23:9443"
	if got[config.RoleCore2]["ens19"] != want {
		t.Errorf("computeFallbackTargets()[core-2][ens19] = %q, want %q (live Observer data should win over the stale static suffix 99)", got[config.RoleCore2]["ens19"], want)
	}
}

func TestComputeFallbackTargets_FallsBackToSuffixWhenObserverHasNotIdentifiedPeer(t *testing.T) {
	cfg := &config.Cluster{
		Role:        config.RoleCore1,
		ControlAddr: "192.168.0.22:9443",
		ScopeDefaults: &config.ScopeDefaults{
			NodeIPSuffixes: map[string]string{config.RoleCore2: "23"},
		},
		Scopes: map[string]config.ScopeConfig{
			"office": {Parent: "ens19", VIP: "10.200.18.254/24"},
		},
	}
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: config.RoleCore1}
	observer := cluster.NewObserver(self, cfg.ControlAddr, nil, "") // no peer ever identified

	got := computeFallbackTargets(cfg, observer)
	want := "10.200.18.23:9443"
	if got[config.RoleCore2]["ens19"] != want {
		t.Errorf("computeFallbackTargets()[core-2][ens19] = %q, want %q (static suffix fallback, Observer has nothing yet)", got[config.RoleCore2]["ens19"], want)
	}
}

func TestComputeFallbackTargets_NilObserverIsSafe(t *testing.T) {
	cfg := &config.Cluster{
		Role:        config.RoleCore1,
		ControlAddr: "192.168.0.22:9443",
		ScopeDefaults: &config.ScopeDefaults{
			NodeIPSuffixes: map[string]string{config.RoleCore2: "23"},
		},
		Scopes: map[string]config.ScopeConfig{
			"office": {Parent: "ens19", VIP: "10.200.18.254/24"},
		},
	}
	got := computeFallbackTargets(cfg, nil)
	want := "10.200.18.23:9443"
	if got[config.RoleCore2]["ens19"] != want {
		t.Errorf("computeFallbackTargets()[core-2][ens19] = %q, want %q (nil observer must not panic)", got[config.RoleCore2]["ens19"], want)
	}
}
