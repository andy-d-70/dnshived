// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"testing"

	"dnshived/internal/config"
)

func TestDNSRecordLine_RoundTripsAllTypes(t *testing.T) {
	cases := []config.DNSRecord{
		{Name: "nas.office.lan", Type: "A", Value: "192.168.100.50"},
		{Name: "nas6.office.lan", Type: "AAAA", Value: "fe80::1"},
		{Name: "printer.office.lan", Type: "CNAME", Value: "nas.office.lan"},
		{Name: "_info.office.lan", Type: "TXT", Value: "a note with spaces"},
		{Name: "50.100.168.192.in-addr.arpa", Type: "PTR", Value: "nas.office.lan"},
		{Name: "mail.office.lan", Type: "MX", Target: "mx1.office.lan", Priority: 10},
		{Name: "_dante._udp.office.lan", Type: "SRV", Target: "nas.office.lan", Port: 4440, Priority: 10, Weight: 20},
		{Name: "office.lan", Type: "NAPTR", Target: "replacement.office.lan", NAPTROrder: 1, Priority: 2, NAPTRFlags: "a", NAPTRService: "b", NAPTRRegexp: "c"},
		{Name: "office.lan", Type: "CAA", CAAFlags: 0, CAATag: "issue", Value: "letsencrypt.org"},
		{Name: "sshfp.office.lan", Type: "RAW", RRType: 44, RRDataHex: "0102030405"},
	}
	for _, want := range cases {
		line := formatDNSRecordLine(want)
		got, err := parseDNSRecordLine(line)
		if err != nil {
			t.Errorf("type %s: parse(%q) error: %v", want.Type, line, err)
			continue
		}
		if got != want {
			t.Errorf("type %s: round-trip mismatch\n line: %q\n got:  %+v\n want: %+v", want.Type, line, got, want)
		}
	}
}

func TestDNSRecordLine_ProbeDisabledRoundTrips(t *testing.T) {
	want := config.DNSRecord{Name: "x.lan", Type: "A", Value: "1.2.3.4", ProbeDisabled: true}
	line := formatDNSRecordLine(want)
	got, err := parseDNSRecordLine(line)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got != want {
		t.Errorf("got %+v, want %+v (line %q)", got, want, line)
	}
}

func TestParseDNSRecordLine_TooFewFieldsRejected(t *testing.T) {
	if _, err := parseDNSRecordLine("A|x.lan"); err == nil {
		t.Fatal("expected an error for a line with only 2 fields")
	}
}

func TestParseDNSRecordLine_WrongArityForTypeRejected(t *testing.T) {
	if _, err := parseDNSRecordLine("SRV|x.lan|target.lan|4440"); err == nil {
		t.Fatal("expected an error: SRV needs target/port/priority/weight, only 2 given")
	}
}

func TestParseDNSRecordLine_UnknownTypeRejected(t *testing.T) {
	if _, err := parseDNSRecordLine("BOGUS|x.lan|1.2.3.4"); err == nil {
		t.Fatal("expected an error for an unknown record type")
	}
}

func TestParseDNSRecordLine_TXTValueMayContainPipe(t *testing.T) {
	got, err := parseDNSRecordLine("TXT|x.lan|a|b|c")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Value != "a|b|c" {
		t.Errorf("Value = %q, want %q (pipes past the 3rd field must survive)", got.Value, "a|b|c")
	}
}

func TestParseDNSRecordLines_SkipsBlankLinesAndParsesEachRecord(t *testing.T) {
	records, err := parseDNSRecordLines("A|a.lan|1.1.1.1\n\n  \nAAAA|b.lan|::1\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(records) != 2 || records[0].Name != "a.lan" || records[1].Name != "b.lan" {
		t.Errorf("records = %+v, want 2 records (a.lan, b.lan)", records)
	}
}

func TestParseDNSRecordLines_FirstErrorStopsParsingAndIsReturned(t *testing.T) {
	_, err := parseDNSRecordLines("A|a.lan|1.1.1.1\nBOGUS|b.lan|x\n")
	if err == nil {
		t.Fatal("expected an error from the second, malformed line")
	}
}

func TestFormatDNSRecordLines_EmptyListProducesEmptyString(t *testing.T) {
	if got := formatDNSRecordLines(nil); got != "" {
		t.Errorf("formatDNSRecordLines(nil) = %q, want empty", got)
	}
}

// TestFormatParseDNSRecordLine_TTLRoundTrip confirms config.DNSRecord.
func TestFormatParseDNSRecordLine_TTLRoundTrip(t *testing.T) {
	r := config.DNSRecord{Name: "a.foo.lan", Type: "A", Value: "192.168.10.1", TTL: 300}
	line := formatDNSRecordLine(r)
	if line != "A|a.foo.lan|192.168.10.1|ttl=300" {
		t.Fatalf("formatted line = %q, want %q", line, "A|a.foo.lan|192.168.10.1|ttl=300")
	}
	got, err := parseDNSRecordLine(line)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.TTL != 300 {
		t.Errorf("parsed TTL = %d, want 300", got.TTL)
	}
	if got.Value != "192.168.10.1" {
		t.Errorf("parsed Value = %q, want unaffected by the trailing ttl= marker", got.Value)
	}
}

// TestParseDNSRecordLine_TTLAndDisabledOrderIndependent confirms both
// trailing markers parse correctly regardless of which order they appear
// in.
func TestParseDNSRecordLine_TTLAndDisabledOrderIndependent(t *testing.T) {
	for _, line := range []string{
		"A|a.foo.lan|192.168.10.1|ttl=60|disabled",
		"A|a.foo.lan|192.168.10.1|disabled|ttl=60",
	} {
		r, err := parseDNSRecordLine(line)
		if err != nil {
			t.Fatalf("parse %q: %v", line, err)
		}
		if r.TTL != 60 || !r.ProbeDisabled {
			t.Errorf("parse %q: TTL=%d ProbeDisabled=%v, want TTL=60 ProbeDisabled=true", line, r.TTL, r.ProbeDisabled)
		}
	}
}

func TestFormatDNSRecordLine_ZeroTTLOmitsMarker(t *testing.T) {
	line := formatDNSRecordLine(config.DNSRecord{Name: "a.foo.lan", Type: "A", Value: "192.168.10.1"})
	if line != "A|a.foo.lan|192.168.10.1" {
		t.Errorf("line = %q, want no ttl= marker", line)
	}
}
