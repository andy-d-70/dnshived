// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsdata

import (
	"encoding/hex"
	"net/netip"
	"testing"
)

func TestRowEncoding_IsStable(t *testing.T) {
	h := Host{Label: "cam-1", Domains: []string{"a.lan", "b.lan"}, Addrs: []Addr{{IP: netip.MustParseAddr("10.0.0.5"), PTR: true}, {IP: netip.MustParseAddr("fd00::5")}}, TTL: 120, ProbeDisabled: true, LastBy: "ann", LastAt: 1790000000}
	r := Record{Host: id(7), Sub: "_x", Owner: "o.lan", Type: 33, TTL: 60, Value: "v", Target: "t.lan", Pref: 5, Prio: 1, Weight: 2, Port: 3, Order: 9, Flags: "s", Service: "SIP", Regexp: "re", CAAFlag: 128, CAATag: "issue", Raw: "ab", Scope: "office", ProbeDisabled: true, LastBy: "bob", LastAt: 5}
	const wantHost = "010563616d2d310201780305612e6c616e0305622e6c616e0405010a000005041100fd0000000000000000000000000000050501010603616e6e070580f7c4d506"
	const wantRec = "01012102013c0310538454127b096493000000000000000704025f7805056f2e6c616e0601760705742e6c616e0801050901010a01020b01030c01730d035349500e0272650f028001100569737375651102616212010913066f66666963651401011503626f62160105"
	if got := hex.EncodeToString(h.Encode()); got != wantHost {
		t.Fatalf("host encoding changed:\n%s", got)
	}
	if got := hex.EncodeToString(r.Encode()); got != wantRec {
		t.Fatalf("record encoding changed:\n%s", got)
	}
}
