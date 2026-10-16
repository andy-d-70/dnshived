// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"testing"

	"dnshived/internal/config"
)

func dhcpStaggerTestCluster() config.Cluster {
	return config.Cluster{
		Scopes: map[string]config.ScopeConfig{
			"office": {
				Parent:    "ens19",
				VLANID:    42,
				VIP:       "192.168.10.254/24",
				NodeIP:    "192.168.10.22/24",
				Gateway:   "192.168.10.1",
				DHCPRange: [2]string{"192.168.10.100", "192.168.10.200"},
			},
		},
	}
}

// TestDHCPConfigChanged_ScopeDHCPRangeEditIsChanged confirms a real scope
// edit that changes central DHCP's own rendered content (its dhcp-range)
// is detected.
func TestDHCPConfigChanged_ScopeDHCPRangeEditIsChanged(t *testing.T) {
	before := dhcpStaggerTestCluster()
	after := dhcpStaggerTestCluster()
	sc := after.Scopes["office"]
	sc.DHCPRange = [2]string{"192.168.10.100", "192.168.10.220"}
	after.Scopes["office"] = sc

	if !dhcpConfigChanged(&before, &after) {
		t.Error("dhcpConfigChanged = false, want true for a real dhcp-range edit")
	}
}

func TestDHCPConfigChanged_UnrelatedFieldEditIsUnchanged(t *testing.T) {
	before := dhcpStaggerTestCluster()
	after := dhcpStaggerTestCluster()
	before.LogLevel = "info"
	after.LogLevel = "debug"

	if dhcpConfigChanged(&before, &after) {
		t.Error("dhcpConfigChanged = true, want false — LogLevel doesn't feed the central DHCP render")
	}
}

// TestDHCPConfigChanged_ReservationOnlyEditIsUnchanged confirms a
// reservation-only edit is NOT reported as DHCP-affecting.
func TestDHCPConfigChanged_ReservationOnlyEditIsUnchanged(t *testing.T) {
	before := dhcpStaggerTestCluster()
	after := dhcpStaggerTestCluster()
	sc := after.Scopes["office"]
	sc.Reservations = []config.Reservation{{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.10.50", Hostname: "nas1"}}
	after.Scopes["office"] = sc

	if dhcpConfigChanged(&before, &after) {
		t.Error("dhcpConfigChanged = true, want false — reservations don't feed Render's own restart-triggering output")
	}
}

// TestDHCPConfigChanged_IdenticalClustersAreUnchanged is the baseline
// no-op case.
func TestDHCPConfigChanged_IdenticalClustersAreUnchanged(t *testing.T) {
	before := dhcpStaggerTestCluster()
	after := dhcpStaggerTestCluster()

	if dhcpConfigChanged(&before, &after) {
		t.Error("dhcpConfigChanged = true, want false for two identical clusters")
	}
}
