// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dhcprelay

import "testing"

func TestVLANSnapshots_CountsPerInterface(t *testing.T) {
	a := &clientInterface{name: "ens19.100"}
	b := &clientInterface{name: "ens19.200"}
	r := &Relay{clientIfaces: []*clientInterface{a, b}}

	a.stats.drop(dropGateClosed)
	a.stats.drop(dropGateClosed)
	b.stats.drop(dropRateLimited)

	snaps := r.VLANSnapshots()
	if len(snaps) != 2 {
		t.Fatalf("snapshots = %d, want 2", len(snaps))
	}
	if got := snaps["ens19.100"].Drops["gate_closed"]; got != 2 {
		t.Errorf("ens19.100 gate_closed = %d, want 2", got)
	}
	if got := snaps["ens19.200"].Drops["gate_closed"]; got != 0 {
		t.Errorf("ens19.200 gate_closed = %d, want 0 (drops must not leak across VLANs)", got)
	}
	if got := snaps["ens19.200"].Drops["rate_limited"]; got != 1 {
		t.Errorf("ens19.200 rate_limited = %d, want 1", got)
	}
}

func TestVLANSnapshots_EveryReasonPresent(t *testing.T) {
	r := &Relay{clientIfaces: []*clientInterface{{name: "ens19.100"}}}
	drops := r.VLANSnapshots()["ens19.100"].Drops
	if len(drops) != int(dropCount) {
		t.Fatalf("reasons in snapshot = %d, want %d (zeros included)", len(drops), int(dropCount))
	}
	for i := dropReason(0); i < dropCount; i++ {
		if _, ok := drops[dropNames[i]]; !ok {
			t.Errorf("reason %q missing from snapshot", dropNames[i])
		}
	}
}
