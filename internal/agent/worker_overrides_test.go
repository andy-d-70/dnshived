// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"testing"

	"dnshived/internal/config"
)

func TestLocalParent_NoPlatformFallsBackToCanonical(t *testing.T) {
	a := New(config.RoleCore1, "test-node", 1, "", "/tmp", testScopes("office"), nil)
	if got := a.localParent("ens19"); got != "ens19" {
		t.Errorf("localParent(ens19) = %q, want ens19 (no Platform set)", got)
	}
}

func TestLocalParent_ResolvesThroughOverride(t *testing.T) {
	a := New(config.RoleCore2, "test-node", 1, "", "/tmp", testScopes("office"), nil)
	a.SetPlatform(&config.Platform{
		Mgmt:    "eth0",
		Workers: []string{"ens19", "ens20"},
		WorkerOverrides: map[string]map[string]string{
			config.RoleCore2: {"ens19": "eth1", "ens20": "eth2"},
		},
	})
	if got := a.localParent("ens19"); got != "eth1" {
		t.Errorf("localParent(ens19) = %q, want eth1 (this node's own override)", got)
	}
	if got := a.localParent("ens20"); got != "eth2" {
		t.Errorf("localParent(ens20) = %q, want eth2 (this node's own override)", got)
	}
}

func TestCheckTrunkLinkState_ResolvesLocalNameButStoresCanonicalKey(t *testing.T) {
	scopes := testScopes("office")
	sc := scopes["office"]
	sc.Parent = "definitely-not-a-real-iface-xyz" // canonical name -- never exists locally
	scopes["office"] = sc
	a := newTestAgent("", scopes)
	a.SetPlatform(&config.Platform{
		Workers: []string{"definitely-not-a-real-iface-xyz"},
		WorkerOverrides: map[string]map[string]string{
			config.RoleCore1: {"definitely-not-a-real-iface-xyz": "lo"},
		},
	})

	found := a.checkTrunkLinkState()
	if len(found) != 0 {
		t.Errorf("checkTrunkLinkState() = %v, want no findings (resolves to lo, which is carrier-up)", found)
	}
	if down, checked := a.trunkLinkDown["definitely-not-a-real-iface-xyz"]; !checked || down {
		t.Errorf("a.trunkLinkDown[canonical] = (checked=%v down=%v), want (true, false)", checked, down)
	}
	if _, checked := a.trunkLinkDown["lo"]; checked {
		t.Error("a.trunkLinkDown must never be keyed by the resolved LOCAL name — only the canonical one")
	}
}

func TestTopoBeaconIfaceSpecs_ResolvesToLocalNames(t *testing.T) {
	scopes := testScopes("office")
	sc := scopes["office"]
	sc.Parent = "ens19"
	scopes["office"] = sc
	a := New(config.RoleCore2, "test-node", 1, "", "/tmp", scopes, nil)
	a.SetPlatform(&config.Platform{
		Workers: []string{"ens19"},
		WorkerOverrides: map[string]map[string]string{
			config.RoleCore2: {"ens19": "eth1"},
		},
	})

	specs := a.topoBeaconIfaceSpecs()
	var found bool
	for _, s := range specs {
		if s.Name == "eth1" {
			found = true
		}
		if s.Name == "ens19" {
			t.Errorf("topoBeaconIfaceSpecs() included the unresolved canonical name %q — must resolve to this node's own local name", s.Name)
		}
	}
	if !found {
		t.Errorf("topoBeaconIfaceSpecs() = %+v, want an entry for the resolved local name eth1", specs)
	}
}
