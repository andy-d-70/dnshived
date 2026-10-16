// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"context"
	"testing"
	"time"

	"dnshived/internal/config"
	"dnshived/internal/topobeacon"
)

func TestTopoBeaconIfaceSpecs_DerivesFromScopesAndMgmt(t *testing.T) {
	a := New(config.RoleCore1, "test-worker-a", 1, "psk", "/tmp", testScopes("office"), nil)
	a.SetMgmtIface("mgmt0")

	specs := a.topoBeaconIfaceSpecs()
	if len(specs) != 2 {
		t.Fatalf("topoBeaconIfaceSpecs() = %+v, want 2 entries (one trunk + mgmt)", specs)
	}
	var sawTrunk, sawMgmt bool
	for _, s := range specs {
		if s.Name == "ens19" && s.Kind == topobeacon.KindTrunk {
			sawTrunk = true
		}
		if s.Name == "mgmt0" && s.Kind == topobeacon.KindMgmt {
			sawMgmt = true
		}
	}
	if !sawTrunk {
		t.Errorf("specs %+v missing the scope's own trunk (ens19)", specs)
	}
	if !sawMgmt {
		t.Errorf("specs %+v missing mgmt0", specs)
	}
}

func TestTopoBeaconIfaceSpecs_NoMgmtConfigured_TrunkOnly(t *testing.T) {
	a := New(config.RoleCore1, "test-worker-a", 1, "psk", "/tmp", testScopes("office"), nil)

	specs := a.topoBeaconIfaceSpecs()
	if len(specs) != 1 || specs[0].Name != "ens19" || specs[0].Kind != topobeacon.KindTrunk {
		t.Fatalf("topoBeaconIfaceSpecs() = %+v, want exactly one trunk entry (ens19)", specs)
	}
}

func TestTopoBeaconIfaceSpecs_NoScopesNoMgmt_Empty(t *testing.T) {
	a := New(config.RoleCore1, "test-worker-a", 1, "psk", "/tmp", nil, nil)

	if specs := a.topoBeaconIfaceSpecs(); len(specs) != 0 {
		t.Fatalf("topoBeaconIfaceSpecs() = %+v, want empty (arbiter-shaped: no scopes, no mgmt set)", specs)
	}
}

func TestTopoBeaconIfaceSpecs_DedupesSharedParent(t *testing.T) {
	scopes := map[string]config.ScopeConfig{
		"a": {Parent: "ens19", VLANID: 10},
		"b": {Parent: "ens19", VLANID: 20},
	}
	a := New(config.RoleCore1, "test-worker-a", 1, "psk", "/tmp", scopes, nil)

	specs := a.topoBeaconIfaceSpecs()
	if len(specs) != 1 {
		t.Fatalf("topoBeaconIfaceSpecs() = %+v, want exactly 1 deduped entry for ens19", specs)
	}
}

func TestTopoSightings_SafeBeforeStart(t *testing.T) {
	a := New(config.RoleCore1, "test-worker-a", 1, "psk", "/tmp", nil, nil)
	if got := a.TopoSightings(); got != nil {
		t.Fatalf("TopoSightings() = %+v before StartTopoBeacon, want nil", got)
	}
}

func TestTopoHeardMgmtFrom_SafeBeforeStart(t *testing.T) {
	a := New(config.RoleCore1, "test-worker-a", 1, "psk", "/tmp", nil, nil)
	if a.TopoHeardMgmtFrom("core-3") {
		t.Fatal("TopoHeardMgmtFrom(core-3) = true before StartTopoBeacon, want false")
	}
}

// TestStartTopoBeacon_RealSocketRoundTrip proves the full path end to end
// on real loopback sockets.
func TestStartTopoBeacon_RealSocketRoundTrip(t *testing.T) {
	scopes := map[string]config.ScopeConfig{"lo-scope": {Parent: "lo", VLANID: 10}}
	a := New(config.RoleCore1, "test-worker-a", 1, "psk", "/tmp", scopes, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	a.StartTopoBeacon(ctx, "core-1", 100*time.Millisecond)

	go topobeacon.SendOnInterface(ctx, "core-3", topobeacon.IfaceSpec{Name: "lo", Kind: topobeacon.KindTrunk}, 100*time.Millisecond)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if a.TopoHeardMgmtFrom("core-3") {
			t.Fatal("TopoHeardMgmtFrom(core-3) = true for a TRUNK-kind beacon, want false (kind must be honored)")
		}
		sightings := a.TopoSightings()
		for _, s := range sightings {
			if s.PeerRole == "core-3" && s.PeerIface == "lo" && s.PeerKind == topobeacon.KindTrunk {
				return // success: real cross-process correlation observed
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("never observed a real beacon from the simulated peer within the deadline")
}

func TestTopoBeaconIfaceSpecs_IncludesScopelessPlatformTrunks(t *testing.T) {
	a := New(config.RoleCore3, "test-core-3", 1, "psk", "/tmp", nil, nil)
	a.SetPlatform(&config.Platform{
		Mgmt:            "ens18",
		Workers:         []string{"ens19", "ens20"},
		WorkerOverrides: map[string]map[string]string{config.RoleCore3: {"ens19": "eth1"}},
	})

	var trunks []string
	for _, s := range a.topoBeaconIfaceSpecs() {
		if s.Kind == topobeacon.KindTrunk {
			trunks = append(trunks, s.Name)
		}
	}
	if len(trunks) != 2 || trunks[0] != "ens20" || trunks[1] != "eth1" {
		t.Fatalf("trunk specs = %v, want [ens20 eth1] (every configured trunk, local names, no scopes needed)", trunks)
	}
}
