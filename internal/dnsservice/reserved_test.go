// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsservice

import (
	"net/netip"
	"testing"

	"dnshived/internal/dnsanswer"
	"dnshived/internal/dnsdata"
)

func TestService_ReservedNamesAreAnsweredAndBeatLeaseNames(t *testing.T) {
	r := newRig(t)
	if _, an := r.answerCount("printer.example.lan", dnsanswer.TypeA); an != 0 {
		t.Fatal("nothing is reserved yet")
	}
	names := []dnsdata.ReservedName{{Name: "printer.example.lan", IP: netip.MustParseAddr("10.0.0.7"), Scope: "office"}}
	r.resv.Store(&names)
	leases := []dnsdata.LeaseName{{Name: "printer.example.lan", IP: netip.MustParseAddr("10.0.0.99"), MAC: "02:00:00:00:00:99", LeasedAt: 1}}
	r.leases.Store(&leases)
	if err := r.svc.Rebuild(false); err != nil {
		t.Fatal(err)
	}
	if rc, an := r.answerCount("printer.example.lan", dnsanswer.TypeA); rc != 0 || an != 1 {
		t.Fatalf("the reserved name answers with its reservation only: rcode %d, %d answers", rc, an)
	}
	if rc, an := r.answerCount("7.0.0.10.in-addr.arpa", dnsanswer.TypePTR); rc != 0 || an != 1 {
		t.Fatalf("the reservation owns its reverse record: rcode %d, %d answers", rc, an)
	}
	names = nil
	r.resv.Store(&names)
	if err := r.svc.Rebuild(false); err != nil {
		t.Fatal(err)
	}
	if _, an := r.answerCount("printer.example.lan", dnsanswer.TypeA); an != 1 {
		t.Fatal("without the reservation the lease name is published again")
	}
}
