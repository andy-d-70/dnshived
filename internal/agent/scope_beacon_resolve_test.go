// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"dnshived/internal/cluster"
	"dnshived/internal/config"
	"dnshived/internal/identity"
	"testing"
	"time"
)

func TestResolveScopePeerAddr_ObserverDerivedWhenNoOverrideOrSuffix(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: config.RoleCore1}
	o := cluster.NewObserver(self, "self-addr", nil, "")
	setPeer(o, "192.0.2.23:9443", config.RoleCore2, true)

	a := New(config.RoleCore1, "self", 1, "psk", "/tmp", nil, o)
	sc := testScopes("office")["office"]

	got := a.resolveScopePeerAddr(sc, config.RoleCore2)
	if got != "192.168.100.23" {
		t.Errorf("resolveScopePeerAddr(office, core-2) = %q, want 192.168.100.23 (derived from Observer, no overrides/suffixes configured)", got)
	}
}

// TestResolveScopePeerAddr_ExplicitOverrideWinsOverObserver confirms
// NodeIPOverrides stays top priority even when Observer HAS also
// identified the peer.
func TestResolveScopePeerAddr_ExplicitOverrideWinsOverObserver(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: config.RoleCore1}
	o := cluster.NewObserver(self, "self-addr", nil, "")
	setPeer(o, "192.0.2.23:9443", config.RoleCore2, true)

	a := New(config.RoleCore1, "self", 1, "psk", "/tmp", nil, o)
	sc := testScopes("office")["office"]
	sc.NodeIPOverrides = map[string]string{config.RoleCore2: "10.9.9.9/24"}

	got := a.resolveScopePeerAddr(sc, config.RoleCore2)
	if got != "10.9.9.9" {
		t.Errorf("resolveScopePeerAddr(office, core-2) = %q, want 10.9.9.9 (explicit override must win over Observer)", got)
	}
}

func TestResolveScopePeerAddr_ObserverWinsOverStaticSuffix(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: config.RoleCore1}
	o := cluster.NewObserver(self, "self-addr", nil, "")
	setPeer(o, "192.0.2.23:9443", config.RoleCore2, true)

	a := New(config.RoleCore1, "self", 1, "psk", "/tmp", nil, o)
	a.SetNodeIPSuffixes(map[string]string{config.RoleCore2: "99"})
	sc := testScopes("office")["office"]

	got := a.resolveScopePeerAddr(sc, config.RoleCore2)
	if got != "192.168.100.23" {
		t.Errorf("resolveScopePeerAddr(office, core-2) = %q, want 192.168.100.23 (live Observer data should win over the stale static suffix 99)", got)
	}
}

func TestResolveScopePeerAddr_FallsBackToStaticSuffixWhenObserverUnidentified(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: config.RoleCore1}
	o := cluster.NewObserver(self, "self-addr", nil, "") // no peer ever identified

	a := New(config.RoleCore1, "self", 1, "psk", "/tmp", nil, o)
	a.SetNodeIPSuffixes(map[string]string{config.RoleCore2: "23"})
	sc := testScopes("office")["office"]

	got := a.resolveScopePeerAddr(sc, config.RoleCore2)
	if got != "192.168.100.23" {
		t.Errorf("resolveScopePeerAddr(office, core-2) = %q, want 192.168.100.23 (static suffix fallback)", got)
	}
}

func TestResolveScopePeerAddr_NilObserverIsSafe(t *testing.T) {
	a := New(config.RoleCore1, "self", 1, "psk", "/tmp", nil, nil)
	a.SetNodeIPSuffixes(map[string]string{config.RoleCore2: "23"})
	sc := testScopes("office")["office"]

	got := a.resolveScopePeerAddr(sc, config.RoleCore2)
	if got != "192.168.100.23" {
		t.Errorf("resolveScopePeerAddr(office, core-2) = %q, want 192.168.100.23 (nil observer must not panic)", got)
	}
}

func TestResolveScopePeerAddr_NoSourceResolvesReturnsEmpty(t *testing.T) {
	a := New(config.RoleCore1, "self", 1, "psk", "/tmp", nil, nil)
	sc := testScopes("office")["office"]

	if got := a.resolveScopePeerAddr(sc, config.RoleCore2); got != "" {
		t.Errorf("resolveScopePeerAddr(office, core-2) = %q, want empty (no source resolves)", got)
	}
}

func TestScopeBeaconLocalAddrs_ExcludesNotYetConstructedScope(t *testing.T) {
	a := &Agent{role: config.RoleCore1, ready: map[string]time.Time{"office": time.Now()}}
	scopes := map[string]config.ScopeConfig{
		"office":       testScopes("office")["office"],
		"just-hotload": {Parent: "ens19", VLANID: 999, NodeIP: "192.168.200.22/24"},
	}
	a.scopes.Store(&scopes)

	got := a.scopeBeaconLocalAddrs()
	if _, ok := got["office"]; !ok {
		t.Errorf("scopeBeaconLocalAddrs() = %+v, missing the real, ready scope 'office'", got)
	}
	if _, ok := got["just-hotload"]; ok {
		t.Errorf("scopeBeaconLocalAddrs() = %+v, includes a NOT-yet-constructed scope — this is exactly the live-found race that produced a permanent bind failure", got)
	}
}

// TestScopeBeaconTargets_ExcludesNotYetConstructedScope mirrors the
// listening-side regression above for the sending side.
func TestScopeBeaconTargets_ExcludesNotYetConstructedScope(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: config.RoleCore1}
	o := cluster.NewObserver(self, "self-addr", nil, "")
	setPeer(o, "192.0.2.23:9443", config.RoleCore2, true)

	a := New(config.RoleCore1, "self", 1, "psk", "/tmp", nil, o)
	scopes := map[string]config.ScopeConfig{
		"office":       testScopes("office")["office"],
		"just-hotload": {Parent: "ens19", VLANID: 999, NodeIP: "192.168.200.22/24"},
	}
	a.scopes.Store(&scopes)
	a.ready = map[string]time.Time{"office": time.Now()}

	targets := a.scopeBeaconTargets()
	for _, target := range targets {
		if target.Scope == "just-hotload" {
			t.Errorf("scopeBeaconTargets() = %+v, includes a target for a NOT-yet-constructed scope", targets)
		}
	}
	sawOffice := false
	for _, target := range targets {
		if target.Scope == "office" {
			sawOffice = true
		}
	}
	if !sawOffice {
		t.Errorf("scopeBeaconTargets() = %+v, missing the real, ready scope 'office'", targets)
	}
}
