// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"testing"

	"dnshived/internal/config"
	"dnshived/internal/leasesync"
)

func TestMergedDHCPLeaseSnapshot_LocalWinsOverPeerOnSameMAC(t *testing.T) {
	a := New(config.RoleCore1, "test-node", 1, "psk", t.TempDir(), testScopes("office"), nil)
	a.localDHCPLeases.Upsert(leasesync.SyncedLease{MAC: "aa:bb", IP: "10.0.0.5", ExpiresAt: 9999999999})
	a.peerDHCPLeases.Upsert(leasesync.SyncedLease{MAC: "aa:bb", IP: "10.0.0.99", ExpiresAt: 9999999999})
	a.peerDHCPLeases.Upsert(leasesync.SyncedLease{MAC: "cc:dd", IP: "10.0.0.6", ExpiresAt: 9999999999})

	got := a.MergedDHCPLeaseSnapshot()
	if len(got) != 2 {
		t.Fatalf("MergedDHCPLeaseSnapshot() = %v, want 2 entries", got)
	}
	byMAC := make(map[string]leasesync.SyncedLease, len(got))
	for _, l := range got {
		byMAC[l.MAC] = l
	}
	if byMAC["aa:bb"].IP != "10.0.0.5" {
		t.Fatalf("MergedDHCPLeaseSnapshot()[aa:bb].IP = %q, want local's own 10.0.0.5 to win over the peer's", byMAC["aa:bb"].IP)
	}
	if byMAC["cc:dd"].IP != "10.0.0.6" {
		t.Fatalf("MergedDHCPLeaseSnapshot()[cc:dd].IP = %q, want the peer-only entry to still be present", byMAC["cc:dd"].IP)
	}
}

func TestTrackLeaseGaps_SelfHealsOnlyAtThreshold(t *testing.T) {
	a := New(config.RoleCore1, "test-node", 1, "psk", t.TempDir(), testScopes("office"), nil)
	gap := []leasesync.SyncedLease{{MAC: "aa:bb", IP: "10.0.0.5", ExpiresAt: 9999999999}}

	for i := 1; i < leaseGapThreshold; i++ {
		toHeal := a.trackLeaseGaps("peer-1", gap)
		if len(toHeal) != 0 {
			t.Fatalf("trackLeaseGaps() round %d returned %v, want nothing before threshold %d", i, toHeal, leaseGapThreshold)
		}
	}
	toHeal := a.trackLeaseGaps("peer-1", gap)
	if len(toHeal) != 1 || toHeal[0].MAC != "aa:bb" {
		t.Fatalf("trackLeaseGaps() at threshold round = %v, want exactly the aa:bb gap", toHeal)
	}
}

func TestTrackLeaseGaps_ResetsWhenGapDisappears(t *testing.T) {
	a := New(config.RoleCore1, "test-node", 1, "psk", t.TempDir(), testScopes("office"), nil)
	gap := []leasesync.SyncedLease{{MAC: "aa:bb", IP: "10.0.0.5", ExpiresAt: 9999999999}}

	a.trackLeaseGaps("peer-1", gap)
	a.trackLeaseGaps("peer-1", gap)
	// Gap resolved — an empty round.
	if toHeal := a.trackLeaseGaps("peer-1", nil); len(toHeal) != 0 {
		t.Fatalf("trackLeaseGaps() on a resolved round returned %v, want nothing", toHeal)
	}
	// Recurs — must start counting from zero again, not continue from 2.
	for i := 1; i < leaseGapThreshold; i++ {
		if toHeal := a.trackLeaseGaps("peer-1", gap); len(toHeal) != 0 {
			t.Fatalf("trackLeaseGaps() recurrence round %d returned %v, want the counter to have reset", i, toHeal)
		}
	}
	if toHeal := a.trackLeaseGaps("peer-1", gap); len(toHeal) != 1 {
		t.Fatalf("trackLeaseGaps() = %v, want the gap to self-heal at threshold after a genuine reset", toHeal)
	}
}

func TestClearLeaseGapCounts_DropsTrackedPeer(t *testing.T) {
	a := New(config.RoleCore1, "test-node", 1, "psk", t.TempDir(), testScopes("office"), nil)
	gap := []leasesync.SyncedLease{{MAC: "aa:bb", IP: "10.0.0.5", ExpiresAt: 9999999999}}
	a.trackLeaseGaps("peer-1", gap)
	a.trackLeaseGaps("peer-1", gap)
	a.clearLeaseGapCounts("peer-1")
	for i := 1; i < leaseGapThreshold; i++ {
		if toHeal := a.trackLeaseGaps("peer-1", gap); len(toHeal) != 0 {
			t.Fatalf("trackLeaseGaps() round %d after clear returned %v, want the counter to have restarted from zero", i, toHeal)
		}
	}
}

func TestCheckLeaseSanity_NoPeersReturnsNil(t *testing.T) {
	a := New(config.RoleCore1, "test-node", 1, "psk", t.TempDir(), testScopes("office"), nil)
	if got := a.CheckLeaseSanity(); got != nil {
		t.Fatalf("CheckLeaseSanity() with no observer = %v, want nil", got)
	}
}

func TestCatchUpLeases_NoPeersIsANoOp(t *testing.T) {
	a := New(config.RoleCore1, "test-node", 1, "psk", t.TempDir(), testScopes("office"), nil)
	a.CatchUpLeases() // must not panic; no observer means nothing to do
	if got := a.peerDHCPLeases.Snapshot(); len(got) != 0 {
		t.Fatalf("peerDHCPLeases after CatchUpLeases() with no observer = %v, want empty", got)
	}
}
