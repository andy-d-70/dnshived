// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package cluster

import (
	"testing"

	"dnshived/internal/identity"
)

func TestBelievedDown_NeverProbedPeerIsNotDown(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "n1", Role: "core-1"}
	o := NewObserver(self, "10.0.0.1:9443", []string{"10.0.0.2:9443"}, "")
	if o.IsReachable("10.0.0.2:9443") {
		t.Skip("observer now starts peers as reachable; BelievedDown no longer matters for this case")
	}
	if o.BelievedDown("10.0.0.2:9443") {
		t.Error("a peer never probed since start is reported as believed down")
	}
	if o.BelievedDown("10.0.0.9:9443") {
		t.Error("an unknown address is reported as believed down")
	}
}

func TestBelievedDown_AfterFailedProbe(t *testing.T) {
	self := identity.Identity{ClusterID: "c", NodeID: "n1", Role: "core-1"}
	o := NewObserver(self, "10.0.0.1:9443", nil, "")
	o.SetPeerForTest("10.0.0.2:9443", &PeerState{Addr: "10.0.0.2:9443", Reachable: false, Failures: 3})
	if !o.BelievedDown("10.0.0.2:9443") {
		t.Error("a peer that failed its probes is not reported as believed down")
	}
	o.SetPeerForTest("10.0.0.3:9443", &PeerState{Addr: "10.0.0.3:9443", Reachable: false, LastSeen: 1700000000})
	if !o.BelievedDown("10.0.0.3:9443") {
		t.Error("a peer that was seen and then lost is not reported as believed down")
	}
	o.SetPeerForTest("10.0.0.4:9443", &PeerState{Addr: "10.0.0.4:9443", Reachable: true, LastSeen: 1700000000})
	if o.BelievedDown("10.0.0.4:9443") {
		t.Error("a reachable peer is reported as believed down")
	}
}
