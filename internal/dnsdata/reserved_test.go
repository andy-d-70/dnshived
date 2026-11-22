// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsdata

import (
	"net/netip"
	"testing"

	"dnshived/internal/config"
	"dnshived/internal/dnsanswer"
)

func reservedCluster() *config.Cluster {
	return &config.Cluster{Scopes: map[string]config.ScopeConfig{
		"b": {Reservations: []config.Reservation{{MAC: "02:00:00:00:00:02", IP: "10.0.0.7", Hostname: "Printer", Names: []string{"print.example.lan", "bad name"}}}},
		"a": {Reservations: []config.Reservation{
			{MAC: "02:00:00:00:00:01", IP: "10.0.0.5", Hostname: "cam"},
			{MAC: "02:00:00:00:00:03", IP: "not-an-ip", Hostname: "skipped"},
			{MAC: "02:00:00:00:00:04", IP: "10.0.0.6", Names: []string{"only-extra"}},
		}},
	}}
}

func TestReservedNames_FollowTheCentralOrderAndSkipWhatDoesNotParse(t *testing.T) {
	var got []string
	for _, n := range ReservedNames(reservedCluster()) {
		got = append(got, n.Scope+":"+n.Name+"="+n.IP.String())
	}
	want := []string{"a:cam=10.0.0.5", "a:only-extra=10.0.0.6", "b:printer=10.0.0.7", "b:print.example.lan=10.0.0.7"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestMergeReserved_AddsAddressAndFirstReverseRecordOnce(t *testing.T) {
	spec := &dnsanswer.Spec{}
	names := []ReservedName{
		{Name: "a.lan", IP: netip.MustParseAddr("10.0.0.1")},
		{Name: "b.lan", IP: netip.MustParseAddr("10.0.0.1")},
		{Name: "v6.lan", IP: netip.MustParseAddr("fd00::1")},
	}
	MergeReserved(spec, names, 60)
	MergeReserved(spec, names, 60)
	got := rrSet{}
	for _, rr := range spec.RRs {
		got[rrKey(rr.Owner, rr.Type, rr.RData)] = true
	}
	w10, _ := dnsanswer.ToWire("a.lan")
	if len(spec.RRs) != 5 || !got[rrKey(dnsanswer.ReverseName(netip.MustParseAddr("10.0.0.1")), dnsanswer.TypePTR, w10)] {
		t.Fatalf("a second merge adds nothing and the first name owns the reverse record: %d records", len(spec.RRs))
	}
	if !got[rrKey("v6.lan", dnsanswer.TypeAAAA, netip.MustParseAddr("fd00::1").AsSlice())] {
		t.Fatal("an IPv6 address gets an AAAA record")
	}
}

func TestMergeReserved_ExistingReverseRecordAndSameNameAreKept(t *testing.T) {
	ip := netip.MustParseAddr("10.0.0.9")
	own, _ := dnsanswer.ToWire("owner.lan")
	spec := &dnsanswer.Spec{RRs: []dnsanswer.RR{
		{Owner: dnsanswer.ReverseName(ip), Type: dnsanswer.TypePTR, TTL: 5, RData: own},
		{Owner: "dup.lan", Type: dnsanswer.TypeA, TTL: 5, RData: ip.AsSlice()},
		{Owner: "dup.lan", Type: dnsanswer.TypeTXT, TTL: 5, RData: []byte{1, 'x'}},
	}}
	MergeReserved(spec, []ReservedName{{Name: "dup.lan", IP: ip}, {Name: "other.lan", IP: netip.MustParseAddr("10.0.0.10")}}, 60)
	var ptrs, as int
	for _, rr := range spec.RRs {
		switch {
		case rr.Type == dnsanswer.TypePTR && rr.Owner == dnsanswer.ReverseName(ip):
			ptrs++
		case rr.Type == dnsanswer.TypeA && rr.Owner == "dup.lan":
			as++
		}
	}
	if ptrs != 1 || as != 1 || len(spec.RRs) != 3+2 {
		t.Fatalf("the authored reverse record and the identical address record are not duplicated: ptr %d a %d total %d", ptrs, as, len(spec.RRs))
	}
}

func TestMergeReserved_ReservedNamesCountAsAuthoredForLeases(t *testing.T) {
	spec := &dnsanswer.Spec{}
	MergeReserved(spec, []ReservedName{{Name: "printer.lan", IP: netip.MustParseAddr("10.0.0.7")}}, 60)
	cols := MergeLeases(spec, []LeaseName{{Name: "printer.lan", IP: netip.MustParseAddr("10.0.0.99"), MAC: "02:00:00:00:00:99"}}, 60)
	if len(cols) != 1 || cols[0].Holder != "authored" {
		t.Fatalf("a lease cannot take a reserved name: %+v", cols)
	}
}

func TestMergeReserved_NothingToAdd(t *testing.T) {
	spec := &dnsanswer.Spec{}
	MergeReserved(spec, nil, 60)
	if len(spec.RRs) != 0 {
		t.Fatal("no names, no records")
	}
}

func TestMergeReserved_AnExplicitReverseRecordSuppressesTheReservationsOwn(t *testing.T) {
	ip := netip.MustParseAddr("10.0.0.3")
	explicit, _ := dnsanswer.ToWire("cam.foo.lan")
	spec := &dnsanswer.Spec{RRs: []dnsanswer.RR{{Owner: dnsanswer.ReverseName(ip), Type: dnsanswer.TypePTR, TTL: 5, RData: explicit}}}
	MergeReserved(spec, []ReservedName{{Name: "www.foo.lan", IP: ip}}, 60)
	var ptrs int
	for _, rr := range spec.RRs {
		if rr.Type == dnsanswer.TypePTR {
			ptrs++
		}
	}
	if ptrs != 1 {
		t.Fatalf("known difference to dnsmasq, which answered both reverse records: %d", ptrs)
	}
}
