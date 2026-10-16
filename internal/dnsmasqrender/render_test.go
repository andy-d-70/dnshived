// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsmasqrender

import (
	"bytes"
	"strings"
	"testing"

	"dnshived/internal/config"
)

// TestDnsmasqTmpl_NoPingOmittedByDefault pins that existing deployments
// see byte-for-byte the same rendered config as before DHCPNoPing existed.
func TestDnsmasqTmpl_NoPingOmittedByDefault(t *testing.T) {
	var buf bytes.Buffer
	if err := Template.Execute(&buf, Data{Scope: "office", Interface: "ens19.100"}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if strings.Contains(buf.String(), "no-ping") {
		t.Errorf("expected no \"no-ping\" line when NoPing is false, got:\n%s", buf.String())
	}
}

func TestDnsmasqTmpl_NoPingRenderedWhenSet(t *testing.T) {
	var buf bytes.Buffer
	if err := Template.Execute(&buf, Data{Scope: "iot", Interface: "ens19.150", NoPing: true}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(buf.String(), "\nno-ping\n") && !strings.HasSuffix(buf.String(), "no-ping\n") {
		t.Errorf("expected a \"no-ping\" line when NoPing is true, got:\n%s", buf.String())
	}
}

func TestDnsmasqTmpl_DefaultLeaseTimeUnchanged(t *testing.T) {
	var buf bytes.Buffer
	data := Data{
		Scope: "office", Interface: "ens19.100",
		DHCPStart: "192.168.100.100", DHCPEnd: "192.168.100.200", LeaseTime: "12h",
		Gateway: "192.168.100.1",
	}
	if err := Template.Execute(&buf, data); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	want := "dhcp-range=192.168.100.100,192.168.100.200,12h\n"
	if !strings.Contains(buf.String(), want) {
		t.Errorf("expected %q in output, got:\n%s", want, buf.String())
	}
	if strings.Contains(buf.String(), "dhcp-broadcast") || strings.Contains(buf.String(), "dhcp-authoritative") {
		t.Errorf("expected no broadcast/authoritative lines by default, got:\n%s", buf.String())
	}
}

func TestDnsmasqTmpl_BroadcastAndAuthoritativeRenderedWhenSet(t *testing.T) {
	var buf bytes.Buffer
	data := Data{Scope: "iot", Interface: "ens19.150", LeaseTime: "24h", Broadcast: true, Authoritative: true}
	if err := Template.Execute(&buf, data); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	got := buf.String()
	for _, want := range []string{"dhcp-broadcast", "dhcp-authoritative"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in output, got:\n%s", want, got)
		}
	}
}

func TestDnsmasqTmpl_NoDNSRecordsOmitsRecordDirectives(t *testing.T) {
	var buf bytes.Buffer
	if err := Template.Execute(&buf, Data{Scope: "office", Interface: "ens19.100"}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	got := buf.String()
	for _, unwanted := range []string{"host-record=", "cname=", "txt-record=", "srv-host="} {
		if strings.Contains(got, unwanted) {
			t.Errorf("expected no %q line with zero DNSRecords, got:\n%s", unwanted, got)
		}
	}
}

// TestDnsmasqTmpl_RendersEachRecordType pins the actual feature: each of
// the 6 supported types maps to its own real dnsmasq directive.
func TestDnsmasqTmpl_RendersEachRecordType(t *testing.T) {
	data := Data{
		Scope: "office", Interface: "ens19.100",
		DNSRecords: []config.DNSRecord{
			{Name: "nas.office.lan", Type: "A", Value: "192.168.100.50"},
			{Name: "nas6.office.lan", Type: "AAAA", Value: "fe80::1"},
			{Name: "printer.office.lan", Type: "CNAME", Value: "nas.office.lan"},
			{Name: "_info.office.lan", Type: "TXT", Value: "a note"},
			{Name: "_dante._udp.office.lan", Type: "SRV", Target: "nas.office.lan", Port: 4440, Priority: 10, Weight: 20},
			{Name: "50.100.168.192.in-addr.arpa", Type: "PTR", Value: "nas.office.lan"},
		},
	}
	var buf bytes.Buffer
	if err := Template.Execute(&buf, data); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	got := buf.String()
	for _, want := range []string{
		"host-record=nas.office.lan,192.168.100.50",
		"host-record=nas6.office.lan,fe80::1",
		"cname=printer.office.lan,nas.office.lan",
		"txt-record=_info.office.lan,a note",
		"srv-host=_dante._udp.office.lan,nas.office.lan,4440,10,20",
		"ptr-record=50.100.168.192.in-addr.arpa,nas.office.lan",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in output, got:\n%s", want, got)
		}
	}
}

func TestDnsmasqTmpl_RendersFullTypeCoverage(t *testing.T) {
	data := Data{
		Scope: "office", Interface: "ens19.100",
		DNSRecords: []config.DNSRecord{
			{Name: "office.lan", Type: "MX", Target: "mail.office.lan", Priority: 10},
			{Name: "_sip._udp.office.lan", Type: "NAPTR", NAPTROrder: 100, Priority: 10,
				NAPTRFlags: "S", NAPTRService: "SIP+D2U", NAPTRRegexp: "", Target: "_sip._udp.office.lan"},
			{Name: "office.lan", Type: "CAA", CAAFlags: 0, CAATag: "issue", Value: "letsencrypt.org"},
			{Name: "raw.office.lan", Type: "RAW", RRType: 65280, RRDataHex: "68656c6c6f"},
			{Name: "bare.office.lan", Type: "RAW", RRType: 65280},
		},
	}
	var buf bytes.Buffer
	if err := Template.Execute(&buf, data); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	got := buf.String()
	for _, want := range []string{
		"mx-host=office.lan,mail.office.lan,10",
		"naptr-record=_sip._udp.office.lan,100,10,S,SIP+D2U,,_sip._udp.office.lan",
		"caa-record=office.lan,0,issue,letsencrypt.org",
		"dns-rr=raw.office.lan,65280,68656c6c6f",
		"dns-rr=bare.office.lan,65280",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in output, got:\n%s", want, got)
		}
	}
	if strings.Contains(got, "dns-rr=bare.office.lan,65280,") {
		t.Errorf("expected no trailing comma/data for a RAW record with no rr_data_hex, got:\n%s", got)
	}
}

func TestEffectiveDHCPBool_OverrideWinsOverBundle(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		name     string
		override *bool
		bundle   bool
		want     bool
	}{
		{"nil override, bundle off", nil, false, false},
		{"nil override, bundle on", nil, true, true},
		{"explicit on, bundle off", &yes, false, true},
		{"explicit off, bundle on", &no, true, false},
	}
	for _, c := range cases {
		if got := EffectiveDHCPBool(c.override, c.bundle); got != c.want {
			t.Errorf("%s: EffectiveDHCPBool = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestRenderReservations_EmptyProducesEmptyText confirms a scope with no
// reservations renders nothing.
func TestRenderReservations_EmptyProducesEmptyText(t *testing.T) {
	text, err := RenderReservations(nil)
	if err != nil {
		t.Fatalf("RenderReservations: %v", err)
	}
	if strings.Contains(text, "dhcp-host") {
		t.Errorf("expected no dhcp-host line for zero reservations, got %q", text)
	}
}

// TestRenderReservations_WithAndWithoutHostname pins the exact dnsmasq
// dhcp-host= syntax.
func TestRenderReservations_WithAndWithoutHostname(t *testing.T) {
	text, err := RenderReservations([]config.Reservation{
		{MAC: "aa:bb:cc:dd:ee:ff", IP: "192.168.100.50"},
		{MAC: "11:22:33:44:55:66", IP: "192.168.100.51", Hostname: "printer"},
	})
	if err != nil {
		t.Fatalf("RenderReservations: %v", err)
	}
	if !strings.Contains(text, "dhcp-host=aa:bb:cc:dd:ee:ff,192.168.100.50\n") {
		t.Errorf("missing hostname-less reservation line, got:\n%s", text)
	}
	if !strings.Contains(text, "dhcp-host=11:22:33:44:55:66,192.168.100.51,printer\n") {
		t.Errorf("missing hostname'd reservation line, got:\n%s", text)
	}
}

func TestRender_ReservationsFlagDerivedFromField(t *testing.T) {
	base := config.ScopeConfig{
		Parent: "ens19", VLANID: 100, DHCPRange: [2]string{"192.168.100.100", "192.168.100.200"},
		Gateway: "192.168.100.1",
	}

	noRes, err := Render("office", base, nil, nil, "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("Render (no reservations): %v", err)
	}
	if strings.Contains(noRes, "reservations-office.conf") {
		t.Errorf("expected no conf-file= reference with zero reservations, got:\n%s", noRes)
	}

	withRes := base
	withRes.Reservations = []config.Reservation{{MAC: "aa:bb:cc:dd:ee:ff", IP: "192.168.100.50"}}
	text, err := Render("office", withRes, nil, nil, "/var/lib/dnshived")
	if err != nil {
		t.Fatalf("Render (with reservations): %v", err)
	}
	if !strings.Contains(text, "conf-file=/var/lib/dnshived/reservations-office.conf") {
		t.Errorf("expected a conf-file= reference with a non-empty Reservations, got:\n%s", text)
	}
}

func TestRenderDNSRecords_TTLHonoredForHostRecordAndCNAME(t *testing.T) {
	records := []config.DNSRecord{
		{Name: "a.foo.lan.", Type: "A", Value: "192.168.10.1", TTL: 300},
		{Name: "c.foo.lan.", Type: "CNAME", Value: "a.foo.lan.", TTL: 60},
		{Name: "mx.foo.lan.", Type: "MX", Target: "mail.foo.lan.", Priority: 10, TTL: 3600},
	}
	text, err := RenderDNSRecords(records)
	if err != nil {
		t.Fatalf("RenderDNSRecords: %v", err)
	}
	if !strings.Contains(text, "host-record=a.foo.lan.,192.168.10.1,300") {
		t.Errorf("A record missing its TTL, got:\n%s", text)
	}
	if !strings.Contains(text, "cname=c.foo.lan.,a.foo.lan.,60") {
		t.Errorf("CNAME record missing its TTL, got:\n%s", text)
	}
	if strings.Contains(text, "3600") {
		t.Errorf("MX record must never render a TTL (dnsmasq --mx-host has no TTL parameter), got:\n%s", text)
	}
}

// TestRenderDNSRecords_ZeroTTLOmitsTrailingField checks a record without
// TTL renders without the TTL field.
func TestRenderDNSRecords_ZeroTTLOmitsTrailingField(t *testing.T) {
	text, err := RenderDNSRecords([]config.DNSRecord{{Name: "a.foo.lan.", Type: "A", Value: "192.168.10.1"}})
	if err != nil {
		t.Fatalf("RenderDNSRecords: %v", err)
	}
	if strings.TrimSpace(text) != "host-record=a.foo.lan.,192.168.10.1" {
		t.Errorf("got %q, want no trailing TTL field", text)
	}
}
