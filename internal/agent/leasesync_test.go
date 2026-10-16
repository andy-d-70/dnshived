// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"os/user"
	"testing"

	"dnshived/internal/config"
	"dnshived/internal/leasesync"
)

func requireDnshivedGroup(t *testing.T) {
	t.Helper()
	if _, err := user.LookupGroup("dnshived"); err != nil {
		t.Skipf("no \"dnshived\" group on this host, skipping: %v", err)
	}
}

func TestMergeReservations_RealReservationWinsOverSameMACShadow(t *testing.T) {
	real := []config.Reservation{{MAC: "AA:BB:CC:DD:EE:01", IP: "10.0.0.5", Hostname: "printer"}}
	local := []leasesync.SyncedLease{{MAC: "aa:bb:cc:dd:ee:01", IP: "10.0.0.99"}} // same MAC, different case, different IP
	got := mergeReservations(real, local, nil)
	if len(got) != 1 {
		t.Fatalf("mergeReservations() = %v, want exactly one entry (real wins)", got)
	}
	if got[0].IP != "10.0.0.5" || got[0].Hostname != "printer" {
		t.Errorf("mergeReservations()[0] = %+v, want the real reservation untouched", got[0])
	}
}

// TestMergeReservations_LocalAndPeerBothIncludedWhenDistinct confirms the
// normal, non-colliding case still surfaces every shadow entry.
func TestMergeReservations_LocalAndPeerBothIncludedWhenDistinct(t *testing.T) {
	local := []leasesync.SyncedLease{{MAC: "aa:aa", IP: "10.0.0.1"}}
	peer := []leasesync.SyncedLease{{MAC: "bb:bb", IP: "10.0.0.2"}}
	got := mergeReservations(nil, local, peer)
	if len(got) != 2 {
		t.Fatalf("mergeReservations() = %v, want both entries present", got)
	}
}

// TestMergeReservations_LocalWinsOverPeerOnSameMAC covers the defensive
// same-MAC-in-both-stores case.
func TestMergeReservations_LocalWinsOverPeerOnSameMAC(t *testing.T) {
	local := []leasesync.SyncedLease{{MAC: "aa:aa", IP: "10.0.0.1"}}
	peer := []leasesync.SyncedLease{{MAC: "aa:aa", IP: "10.0.0.9"}}
	got := mergeReservations(nil, local, peer)
	if len(got) != 1 {
		t.Fatalf("mergeReservations() = %v, want exactly one entry for the colliding MAC", got)
	}
	if got[0].IP != "10.0.0.1" {
		t.Errorf("mergeReservations()[0].IP = %q, want local's own value 10.0.0.1 to win", got[0].IP)
	}
}

func TestMacHasRealReservation_TrueForConfiguredMAC(t *testing.T) {
	scopes := map[string]config.ScopeConfig{
		"office": {Reservations: []config.Reservation{{MAC: "AA:BB:CC:DD:EE:01", IP: "10.0.0.5"}}},
	}
	a := New(config.RoleCore1, "test-worker-a", 1, "psk", "/tmp", scopes, nil)
	if !a.macHasRealReservation("aa:bb:cc:dd:ee:01") {
		t.Error("macHasRealReservation() = false for a MAC with a real reservation (case-insensitive), want true")
	}
	if a.macHasRealReservation("ff:ff:ff:ff:ff:ff") {
		t.Error("macHasRealReservation() = true for an unrelated MAC, want false")
	}
}

// TestDynamicDNSHosts_PublishesHostnamedLease checks a lease's DHCP
// hostname is published to DNS.
func TestDynamicDNSHosts_PublishesHostnamedLease(t *testing.T) {
	local := []leasesync.SyncedLease{{MAC: "aa:aa", IP: "10.0.0.5", Hostname: "laptop1"}}
	got := dynamicDNSHosts(nil, nil, local, nil)
	if len(got) != 1 || got[0].Hostname != "laptop1" || got[0].IP != "10.0.0.5" {
		t.Fatalf("dynamicDNSHosts() = %+v, want one entry (laptop1, 10.0.0.5)", got)
	}
}

// TestDynamicDNSHosts_SkipsLeaseWithNoHostname covers the common case
// (most clients never send option 12) — no name, nothing to publish.
func TestDynamicDNSHosts_SkipsLeaseWithNoHostname(t *testing.T) {
	local := []leasesync.SyncedLease{{MAC: "aa:aa", IP: "10.0.0.5"}}
	if got := dynamicDNSHosts(nil, nil, local, nil); len(got) != 0 {
		t.Errorf("dynamicDNSHosts() = %+v, want empty for a hostname-less lease", got)
	}
}

func TestDynamicDNSHosts_SkipsMACWithRealReservation(t *testing.T) {
	scopes := map[string]config.ScopeConfig{
		"office": {Reservations: []config.Reservation{{MAC: "AA:AA", IP: "10.0.0.5"}}},
	}
	local := []leasesync.SyncedLease{{MAC: "aa:aa", IP: "10.0.0.5", Hostname: "laptop1"}}
	if got := dynamicDNSHosts(scopes, nil, local, nil); len(got) != 0 {
		t.Errorf("dynamicDNSHosts() = %+v, want empty — this MAC's own address is already reserved", got)
	}
}

func TestDynamicDNSHosts_SkipsNameCollidingWithStaticContent(t *testing.T) {
	lease := []leasesync.SyncedLease{{MAC: "aa:aa", IP: "10.0.0.5", Hostname: "nas1"}}

	t.Run("scope DNSRecords", func(t *testing.T) {
		scopes := map[string]config.ScopeConfig{
			"office": {DNSRecords: []config.DNSRecord{{Name: "nas1", Type: "A", Value: "10.0.0.99"}}},
		}
		if got := dynamicDNSHosts(scopes, nil, lease, nil); len(got) != 0 {
			t.Errorf("dynamicDNSHosts() = %+v, want empty — name collides with a scope DNS record", got)
		}
	})
	t.Run("another reservation's Hostname", func(t *testing.T) {
		scopes := map[string]config.ScopeConfig{
			"office": {Reservations: []config.Reservation{{MAC: "BB:BB", IP: "10.0.0.6", Hostname: "nas1"}}},
		}
		if got := dynamicDNSHosts(scopes, nil, lease, nil); len(got) != 0 {
			t.Errorf("dynamicDNSHosts() = %+v, want empty — name collides with a different MAC's real reservation", got)
		}
	})
	t.Run("GlobalDNSRecords", func(t *testing.T) {
		global := []config.DNSRecord{{Name: "nas1", Type: "A", Value: "10.0.0.99"}}
		if got := dynamicDNSHosts(nil, global, lease, nil); len(got) != 0 {
			t.Errorf("dynamicDNSHosts() = %+v, want empty — name collides with a global DNS record", got)
		}
	})
}

// TestDynamicDNSHosts_LocalWinsOverPeerOnSameMAC mirrors
// TestMergeReservations_LocalWinsOverPeerOnSameMAC exactly, for the
// DNS-publishing side.
func TestDynamicDNSHosts_LocalWinsOverPeerOnSameMAC(t *testing.T) {
	local := []leasesync.SyncedLease{{MAC: "aa:aa", IP: "10.0.0.1", Hostname: "local-name"}}
	peer := []leasesync.SyncedLease{{MAC: "aa:aa", IP: "10.0.0.9", Hostname: "peer-name"}}
	got := dynamicDNSHosts(nil, nil, local, peer)
	if len(got) != 1 || got[0].Hostname != "local-name" {
		t.Fatalf("dynamicDNSHosts() = %+v, want local's own entry to win", got)
	}
}

// TestReleaseLease_UnconfiguredScopeErrors and
// TestReleaseLease_ScopeWithNoNodeIPErrors cover ReleaseLease's own
// giaddr-resolution error paths.
func TestReleaseLease_UnconfiguredScopeErrors(t *testing.T) {
	a := New(config.RoleCore1, "test-worker-a", 1, "psk", t.TempDir(), nil, nil)
	if err := a.ReleaseLease("no-such-scope", "aa:aa", "10.0.0.5"); err == nil {
		t.Error("expected an error for a scope this node doesn't have configured")
	}
}

func TestReleaseLease_ScopeWithNoNodeIPErrors(t *testing.T) {
	scopes := map[string]config.ScopeConfig{"office": {}}
	a := New(config.RoleCore1, "test-worker-a", 1, "psk", t.TempDir(), scopes, nil)
	if err := a.ReleaseLease("office", "aa:aa", "10.0.0.5"); err == nil {
		t.Error("expected an error for a scope with no node_ip on this node")
	}
}
