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

func TestRowEncoding_OwnTTLZeroIsKeptApartFromNoTTL(t *testing.T) {
	tests := []struct {
		name    string
		body    []byte
		want    string
		decode  func([]byte) (uint32, bool, error)
		wantTTL uint32
		wantOwn bool
	}{
		{"host without own ttl", (&Host{Label: "a"}).Encode(), "010161", hostTTL, 0, false},
		{"host with own ttl 0", (&Host{Label: "a", OwnTTL: true}).Encode(), "010161020100", hostTTL, 0, true},
		{"host with ttl 120", (&Host{Label: "a", TTL: 120}).Encode(), "010161020178", hostTTL, 120, true},
		{"record without own ttl", (&Record{Type: 16}).Encode(), "010110", recordTTL, 0, false},
		{"record with own ttl 0", (&Record{Type: 16, OwnTTL: true}).Encode(), "010110020100", recordTTL, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hex.EncodeToString(tt.body); got != tt.want {
				t.Fatalf("bytes %s, want %s", got, tt.want)
			}
			ttl, own, err := tt.decode(tt.body)
			if err != nil || ttl != tt.wantTTL || own != tt.wantOwn {
				t.Fatalf("decoded ttl %d own %v err %v, want %d %v", ttl, own, err, tt.wantTTL, tt.wantOwn)
			}
		})
	}
}

func hostTTL(b []byte) (uint32, bool, error) {
	h, err := DecodeHost(b)
	return h.TTL, h.OwnTTL, err
}

func recordTTL(b []byte) (uint32, bool, error) {
	r, err := DecodeRecord(b)
	return r.TTL, r.OwnTTL, err
}
