// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package topobeacon

import (
	"context"
	"testing"
	"time"
)

func TestStore_RecordThenSnapshot_ReturnsCorrelation(t *testing.T) {
	s := NewStore(5*time.Second, "core-1")
	s.record("ens19", KindTrunk, Beacon{Magic: Magic, Role: "core-3", Iface: "eth1", Kind: KindTrunk})

	got := s.Snapshot()
	if len(got) != 1 {
		t.Fatalf("Snapshot() = %d entries, want 1", len(got))
	}
	sig := got[0]
	if sig.MyIface != "ens19" || sig.PeerRole != "core-3" || sig.PeerIface != "eth1" || sig.PeerKind != KindTrunk {
		t.Fatalf("unexpected sighting: %+v", sig)
	}
	if sig.Count != 1 {
		t.Fatalf("Count = %d, want 1", sig.Count)
	}
}

func TestStore_RepeatedBeacon_IncrementsCountAndRefreshesLastSeen(t *testing.T) {
	s := NewStore(5*time.Second, "")
	b := Beacon{Magic: Magic, Role: "core-2", Iface: "ens20", Kind: KindTrunk}
	s.record("ens20", KindTrunk, b)
	s.record("ens20", KindTrunk, b)
	s.record("ens20", KindTrunk, b)

	got := s.Snapshot()
	if len(got) != 1 {
		t.Fatalf("Snapshot() = %d entries, want 1 (same pairing repeated)", len(got))
	}
	if got[0].Count != 3 {
		t.Fatalf("Count = %d, want 3", got[0].Count)
	}
}

func TestStore_SelfRole_DropsSelfBeacon(t *testing.T) {
	s := NewStore(5*time.Second, "core-1")
	s.record("ens19", KindTrunk, Beacon{Magic: Magic, Role: "core-1", Iface: "ens19", Kind: KindTrunk})

	if got := s.Snapshot(); len(got) != 0 {
		t.Fatalf("Snapshot() = %d entries, want 0 (self-beacon must be dropped)", len(got))
	}
}

func TestStore_SelfRole_EmptyDisablesFiltering(t *testing.T) {
	s := NewStore(5*time.Second, "") // no self-role configured
	s.record("ens19", KindTrunk, Beacon{Magic: Magic, Role: "core-1", Iface: "ens19", Kind: KindTrunk})

	if got := s.Snapshot(); len(got) != 1 {
		t.Fatalf("Snapshot() = %d entries, want 1 (no selfRole set, nothing should be filtered)", len(got))
	}
}

func TestStore_Snapshot_PrunesStaleEntries(t *testing.T) {
	s := NewStore(1*time.Millisecond, "") // staleAfterFactor(4) * 1ms = 4ms cutoff
	s.record("ens19", KindTrunk, Beacon{Magic: Magic, Role: "core-2", Iface: "ens19", Kind: KindTrunk})

	time.Sleep(20 * time.Millisecond)

	got := s.Snapshot()
	if len(got) != 0 {
		t.Fatalf("Snapshot() = %d entries, want 0 (entry should have gone stale)", len(got))
	}
}

func TestStore_Snapshot_FreshEntrySurvives(t *testing.T) {
	s := NewStore(1*time.Hour, "") // stale cutoff far in the future
	s.record("ens19", KindTrunk, Beacon{Magic: Magic, Role: "core-2", Iface: "ens19", Kind: KindTrunk})

	got := s.Snapshot()
	if len(got) != 1 {
		t.Fatalf("Snapshot() = %d entries, want 1 (entry is fresh, must not be pruned)", len(got))
	}
}

func TestStore_HeardFrom_MatchesRoleAndKind(t *testing.T) {
	s := NewStore(1*time.Hour, "core-1")
	s.record("mgmt0", KindMgmt, Beacon{Magic: Magic, Role: "core-3", Iface: "mgmt0", Kind: KindMgmt})

	if !s.HeardFrom("core-3", KindMgmt) {
		t.Fatal("HeardFrom(core-3, mgmt) = false, want true")
	}
	if s.HeardFrom("core-3", KindTrunk) {
		t.Fatal("HeardFrom(core-3, trunk) = true, want false (only an mgmt beacon was heard)")
	}
	if s.HeardFrom("core-2", KindMgmt) {
		t.Fatal("HeardFrom(core-2, mgmt) = true, want false (never heard from core-2)")
	}
}

func TestStore_MultipleInterfacesAndPeers_AllRecordedIndependently(t *testing.T) {
	s := NewStore(1*time.Hour, "core-1")
	s.record("ens19", KindTrunk, Beacon{Magic: Magic, Role: "core-2", Iface: "ens19", Kind: KindTrunk})
	s.record("ens20", KindTrunk, Beacon{Magic: Magic, Role: "core-2", Iface: "ens20", Kind: KindTrunk})
	s.record("ens19", KindTrunk, Beacon{Magic: Magic, Role: "core-3", Iface: "eth1", Kind: KindTrunk})
	s.record("mgmt0", KindMgmt, Beacon{Magic: Magic, Role: "core-3", Iface: "mgmt0", Kind: KindMgmt})

	got := s.Snapshot()
	if len(got) != 4 {
		t.Fatalf("Snapshot() = %d entries, want 4 distinct pairings, got %+v", len(got), got)
	}
}

func TestSendAndListen_RealRoundTripOnLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	store := NewStore(200*time.Millisecond, "core-1")
	go listenOnInterface(ctx, IfaceSpec{Name: "lo", Kind: KindTrunk}, store)
	time.Sleep(50 * time.Millisecond) // let the listener's own bind land before the first send

	go SendOnInterface(ctx, "core-3", IfaceSpec{Name: "lo", Kind: KindTrunk}, 100*time.Millisecond)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := store.Snapshot(); len(got) == 1 {
			sig := got[0]
			if sig.MyIface != "lo" || sig.PeerRole != "core-3" || sig.PeerIface != "lo" {
				t.Fatalf("unexpected sighting over real socket: %+v", sig)
			}
			return // success
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("never received a real beacon over the loopback round trip within the deadline")
}

func TestSortSightings_DeterministicOrder(t *testing.T) {
	in := []Sighting{
		{MyIface: "ens20", PeerRole: "core-3", PeerIface: "eth2"},
		{MyIface: "ens19", PeerRole: "core-3", PeerIface: "eth1"},
		{MyIface: "ens19", PeerRole: "core-2", PeerIface: "ens19"},
	}
	sortSightings(in)

	want := []string{"ens19|core-2|ens19", "ens19|core-3|eth1", "ens20|core-3|eth2"}
	for i, s := range in {
		got := sightingKey(s.MyIface, s.PeerRole, s.PeerIface)
		if got != want[i] {
			t.Fatalf("sorted[%d] = %q, want %q", i, got, want[i])
		}
	}
}
