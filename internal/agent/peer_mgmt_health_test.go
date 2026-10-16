// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"strings"
	"testing"

	"dnshived/internal/cluster"
	"dnshived/internal/config"
	"dnshived/internal/identity"
)

func TestCheckPeerMgmtHealth_ReportsPeerAlivePrimaryDownFallbackUp(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: config.RoleCore1}
	o := cluster.NewObserver(self, "self-addr", nil, "")
	o.SetPeerForTest("core-2-addr", &cluster.PeerState{
		Addr:      "core-2-addr",
		Reachable: false,
		Identity:  &identity.Identity{ClusterID: "c", NodeID: "n2", Role: config.RoleCore2},
	})
	o.SetFallbackStatusForTest(config.RoleCore2, "ens19", cluster.FallbackStatus{
		Role: config.RoleCore2, Addr: "10.200.18.23:9443", Reachable: true,
	})

	a := New(config.RoleCore1, "self", 1, "psk", "/tmp", testScopes("office"), o)

	found := a.checkPeerMgmtHealth()
	if len(found) != 1 {
		t.Fatalf("checkPeerMgmtHealth() = %v, want exactly 1 finding", found)
	}
	f := found[0]
	if f.What != "peer_mgmt_down" {
		t.Errorf("f.What = %q, want peer_mgmt_down", f.What)
	}
	if f.Scope != config.RoleCore2 {
		t.Errorf("f.Scope = %q, want core-2 (role reused via Scope, same convention as checkTrunkLinkState)", f.Scope)
	}
	if f.Healable {
		t.Error("f.Healable = true, want false (nothing here for this node to reconstruct/self-heal)")
	}
	if !strings.Contains(f.Detail, "core-2-addr") || !strings.Contains(f.Detail, "10.200.18.23:9443") {
		t.Errorf("f.Detail = %q, want it to name both the dead primary address and the alive fallback address", f.Detail)
	}
}

func TestCheckPeerMgmtHealth_ReachablePeerReportsNothing(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: config.RoleCore1}
	o := cluster.NewObserver(self, "self-addr", nil, "")
	o.SetPeerForTest("core-2-addr", &cluster.PeerState{
		Addr:      "core-2-addr",
		Reachable: true,
		Identity:  &identity.Identity{ClusterID: "c", NodeID: "n2", Role: config.RoleCore2},
	})
	o.SetFallbackStatusForTest(config.RoleCore2, "ens19", cluster.FallbackStatus{
		Role: config.RoleCore2, Addr: "10.200.18.23:9443", Reachable: true,
	})

	a := New(config.RoleCore1, "self", 1, "psk", "/tmp", testScopes("office"), o)

	if found := a.checkPeerMgmtHealth(); len(found) != 0 {
		t.Errorf("checkPeerMgmtHealth() = %v, want no findings for a reachable peer", found)
	}
}

func TestCheckPeerMgmtHealth_BothPathsDownReportsNothing(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: config.RoleCore1}
	o := cluster.NewObserver(self, "self-addr", nil, "")
	o.SetPeerForTest("core-2-addr", &cluster.PeerState{
		Addr:      "core-2-addr",
		Reachable: false,
		Identity:  &identity.Identity{ClusterID: "c", NodeID: "n2", Role: config.RoleCore2},
	})
	o.SetFallbackStatusForTest(config.RoleCore2, "ens19", cluster.FallbackStatus{
		Role: config.RoleCore2, Addr: "10.200.18.23:9443", Reachable: false, LastError: "dial timeout",
	})

	a := New(config.RoleCore1, "self", 1, "psk", "/tmp", testScopes("office"), o)

	if found := a.checkPeerMgmtHealth(); len(found) != 0 {
		t.Errorf("checkPeerMgmtHealth() = %v, want no findings — peer is genuinely fully unreachable, not just mgmt-down", found)
	}
}

func TestCheckPeerMgmtHealth_NoIdentityYetReportsNothing(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "self", Role: config.RoleCore1}
	o := cluster.NewObserver(self, "self-addr", nil, "")
	o.SetPeerForTest("core-2-addr", &cluster.PeerState{Addr: "core-2-addr", Reachable: false, Identity: nil})
	o.SetFallbackStatusForTest(config.RoleCore2, "ens19", cluster.FallbackStatus{
		Role: config.RoleCore2, Addr: "10.200.18.23:9443", Reachable: true,
	})

	a := New(config.RoleCore1, "self", 1, "psk", "/tmp", testScopes("office"), o)

	if found := a.checkPeerMgmtHealth(); len(found) != 0 {
		t.Errorf("checkPeerMgmtHealth() = %v, want no findings (no cached identity to correlate)", found)
	}
}

// TestCheckPeerMgmtHealth_NilObserverReportsNothing confirms a
// observer-less agent never panics.
func TestCheckPeerMgmtHealth_NilObserverReportsNothing(t *testing.T) {
	a := New(config.RoleCore1, "self", 1, "psk", "/tmp", testScopes("office"), nil)
	if found := a.checkPeerMgmtHealth(); len(found) != 0 {
		t.Errorf("checkPeerMgmtHealth() = %v, want no findings (no observer at all)", found)
	}
}
