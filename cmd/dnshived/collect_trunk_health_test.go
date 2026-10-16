// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"testing"
	"time"

	"dnshived/internal/agent"
	"dnshived/internal/cluster"
	"dnshived/internal/desired"
	"dnshived/internal/eventlog"
	"dnshived/internal/fencing"
	"dnshived/internal/fsm"
	"dnshived/internal/identity"
	"dnshived/internal/lease"
)

// newTestReconcileLoop builds a real reconcileLoop for inspecting its
// collectors.
func newTestReconcileLoop(t *testing.T) (*reconcileLoop, *eventlog.Ring) {
	t.Helper()
	self := identity.Identity{ClusterID: "test-cluster", NodeID: "self", Role: "core-1"}
	observer := cluster.NewObserver(self, "self-addr", nil, "")
	watermark, err := fencing.NewWatermark("")
	if err != nil {
		t.Fatalf("NewWatermark: %v", err)
	}
	events := eventlog.New(100, "self")
	return &reconcileLoop{
		observer:    observer,
		machine:     fsm.New(1),
		engine:      desired.New(1, nil, 60*time.Second, 0),
		leaseMgr:    lease.NewManager("core-1", lease.DefaultTTL),
		watermark:   watermark,
		ag:          agent.New("core-1", "self", 1, "", t.TempDir(), nil, observer),
		events:      events,
		role:        "core-1",
		incarnation: 1,
	}, events
}

func TestCollectTrunkHealth_IncludesSelfAndIdentifiedPeers(t *testing.T) {
	rl, _ := newTestReconcileLoop(t)
	rl.observer.SetPeerForTest("core-2-addr", &cluster.PeerState{
		Addr: "core-2-addr",
		Identity: &identity.Identity{
			ClusterID: "test-cluster", NodeID: "n2", Role: "core-2",
			TrunkHealth: map[string]bool{"ens19": false},
		},
	})

	got := rl.collectTrunkHealth()
	if _, ok := got["core-1"]; !ok {
		t.Error(`collectTrunkHealth()["core-1"] missing — self's own role must always contribute an entry`)
	}
	if h, ok := got["core-2"]; !ok || h["ens19"] != false {
		t.Errorf(`collectTrunkHealth()["core-2"] = %v, want {ens19:false}`, got["core-2"])
	}
	if _, ok := got["core-3"]; ok {
		t.Error(`collectTrunkHealth()["core-3"] present, want absent (never identified)`)
	}
}

func TestCollectTrunkScore_SelfIsLocalOthersUseLocalWhenPathUnknown(t *testing.T) {
	rl, _ := newTestReconcileLoop(t)
	rl.observer.SetPeerForTest("core-2-addr", &cluster.PeerState{
		Addr: "core-2-addr",
		Identity: &identity.Identity{
			ClusterID: "test-cluster", NodeID: "n2", Role: "core-2",
			TrunkScore: map[string]int{"ens19": 90, "ens20": 40},
		},
	})

	got := rl.collectTrunkScore()
	if _, ok := got["core-1"]; !ok {
		t.Error(`collectTrunkScore()["core-1"] missing -- self must always contribute`)
	}
	core2, ok := got["core-2"]
	if !ok {
		t.Fatal(`collectTrunkScore()["core-2"] missing -- an identified peer must contribute`)
	}
	if core2["ens19"] != 90 || core2["ens20"] != 40 {
		t.Errorf(`collectTrunkScore()["core-2"] = %v, want {ens19:90 ens20:40} (local score, no path score known)`, core2)
	}
	if _, ok := got["core-3"]; ok {
		t.Error(`collectTrunkScore()["core-3"] present, want absent (never identified)`)
	}
}

func TestEffectiveTrunkScore(t *testing.T) {
	cases := []struct {
		name        string
		local, path int
		pathKnown   bool
		want        int
	}{
		{"path lower than local, both known", 90, 40, true, 40},
		{"local lower than path, both known", 40, 90, true, 40},
		{"equal", 70, 70, true, 70},
		{"path unknown -- local alone", 90, 0, false, 90},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := effectiveTrunkScore(c.local, c.path, c.pathKnown); got != c.want {
				t.Errorf("effectiveTrunkScore(%d, %d, %v) = %d, want %d", c.local, c.path, c.pathKnown, got, c.want)
			}
		})
	}
}
