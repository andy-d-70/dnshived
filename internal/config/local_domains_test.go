// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package config

import "testing"

func TestLocalDomain_ExpandedRecords_ApexAndHostLabel(t *testing.T) {
	d := LocalDomain{
		Name: "foo.lan",
		Records: []LocalDomainHost{
			{Host: "", Type: "A", Value: "192.168.10.5"},
			{Host: "@", Type: "A", Value: "192.168.10.6"},
			{Host: "nas1", Type: "A", Value: "192.168.10.20"},
		},
	}
	recs := d.ExpandedRecords()
	if len(recs) != 3 {
		t.Fatalf("got %d records, want 3", len(recs))
	}
	if recs[0].Name != "foo.lan." {
		t.Errorf("apex (empty host) Name = %q, want %q", recs[0].Name, "foo.lan.")
	}
	if recs[1].Name != "foo.lan." {
		t.Errorf("apex (@) Name = %q, want %q", recs[1].Name, "foo.lan.")
	}
	if recs[2].Name != "nas1.foo.lan." {
		t.Errorf("host label Name = %q, want %q", recs[2].Name, "nas1.foo.lan.")
	}
}

func TestLocalDomain_ExpandedRecords_TTLResolution(t *testing.T) {
	d := LocalDomain{
		Name: "foo.lan",
		TTL:  3600,
		Records: []LocalDomainHost{
			{Host: "a", Type: "A", Value: "192.168.10.1"},          // no own TTL -> domain default
			{Host: "b", Type: "A", Value: "192.168.10.2", TTL: 60}, // own TTL wins
		},
	}
	recs := d.ExpandedRecords()
	if recs[0].TTL != 3600 {
		t.Errorf("host a TTL = %d, want domain default 3600", recs[0].TTL)
	}
	if recs[1].TTL != 60 {
		t.Errorf("host b TTL = %d, want its own override 60, not the domain default", recs[1].TTL)
	}
}

func TestExpandedLocalDomainRecords_AppliesAcrossEveryDomain(t *testing.T) {
	domains := []LocalDomain{
		{Name: "foo.lan", Records: []LocalDomainHost{{Host: "a", Type: "A", Value: "10.0.0.1"}}},
		{Name: "bar.lan", Records: []LocalDomainHost{{Host: "b", Type: "A", Value: "10.0.0.2"}}},
	}
	recs := ExpandedLocalDomainRecords(domains)
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
	if recs[0].Name != "a.foo.lan." || recs[1].Name != "b.bar.lan." {
		t.Errorf("unexpected names: %+v", recs)
	}
}

func TestValidateLocalDomains_RejectsBadName(t *testing.T) {
	err := validateLocalDomains([]LocalDomain{{Name: "not a domain!"}})
	if err == nil {
		t.Fatal("expected an error for an invalid domain name")
	}
}

func TestValidateLocalDomains_RejectsDuplicateName(t *testing.T) {
	err := validateLocalDomains([]LocalDomain{{Name: "foo.lan"}, {Name: "FOO.LAN"}})
	if err == nil {
		t.Fatal("expected an error for a duplicate (case-insensitive) domain name")
	}
}

func TestValidateLocalDomains_RejectsNegativeTTL(t *testing.T) {
	err := validateLocalDomains([]LocalDomain{{Name: "foo.lan", TTL: -1}})
	if err == nil {
		t.Fatal("expected an error for a negative domain TTL")
	}
}

func TestValidateLocalDomains_RejectsNegativeHostTTL(t *testing.T) {
	err := validateLocalDomains([]LocalDomain{{
		Name:    "foo.lan",
		Records: []LocalDomainHost{{Host: "a", Type: "A", Value: "10.0.0.1", TTL: -5}},
	}})
	if err == nil {
		t.Fatal("expected an error for a negative host TTL")
	}
}

func TestValidateLocalDomains_ReusesDNSRecordTypeValidation(t *testing.T) {
	err := validateLocalDomains([]LocalDomain{{
		Name:    "foo.lan",
		Records: []LocalDomainHost{{Host: "svc", Type: "SRV"}},
	}})
	if err == nil {
		t.Fatal("expected an error for an incomplete SRV record")
	}
}

func TestValidateLocalDomains_ValidDomainAccepted(t *testing.T) {
	err := validateLocalDomains([]LocalDomain{{
		Name: "foo.lan",
		TTL:  3600,
		Records: []LocalDomainHost{
			{Host: "", Type: "A", Value: "192.168.10.1"},
			{Host: "nas1", Type: "A", Value: "192.168.10.20", TTL: 60},
			{Host: "_dnc._sub._dns-sd._udp", Type: "SRV", Target: "dnc.foo.lan.", Port: 8000},
		},
	}})
	if err != nil {
		t.Fatalf("unexpected error for a valid domain: %v", err)
	}
}

func TestPropagateForkedDomains_DirectForkSyncsTTLAndRecords(t *testing.T) {
	domains := []LocalDomain{
		{Name: "foo.lan", TTL: 3600, Records: []LocalDomainHost{{Host: "nas1", Type: "A", Value: "10.0.0.1"}}},
		{Name: "fork.lan", TTL: 60, ForkedFrom: "foo.lan", Records: []LocalDomainHost{{Host: "old", Type: "A", Value: "1.2.3.4"}}},
	}
	out := PropagateForkedDomains(domains, "foo.lan")
	var fork LocalDomain
	for _, d := range out {
		if d.Name == "fork.lan" {
			fork = d
		}
	}
	if fork.TTL != 3600 {
		t.Errorf("fork.lan TTL = %d, want 3600 (synced from parent)", fork.TTL)
	}
	if len(fork.Records) != 1 || fork.Records[0].Host != "nas1" {
		t.Errorf("fork.lan Records = %+v, want a copy of foo.lan's own records", fork.Records)
	}
}

func TestPropagateForkedDomains_TransitiveForkOfAForkSyncs(t *testing.T) {
	domains := []LocalDomain{
		{Name: "foo.lan", TTL: 100, Records: []LocalDomainHost{{Host: "a", Type: "A", Value: "1.1.1.1"}}},
		{Name: "mid.lan", ForkedFrom: "foo.lan"},
		{Name: "leaf.lan", ForkedFrom: "mid.lan"},
	}
	out := PropagateForkedDomains(domains, "foo.lan")
	byName := make(map[string]LocalDomain, len(out))
	for _, d := range out {
		byName[d.Name] = d
	}
	if byName["leaf.lan"].TTL != 100 || len(byName["leaf.lan"].Records) != 1 {
		t.Errorf("leaf.lan = %+v, want it transitively synced through mid.lan to foo.lan's own content", byName["leaf.lan"])
	}
}

func TestPropagateForkedDomains_UnrelatedDomainUntouched(t *testing.T) {
	domains := []LocalDomain{
		{Name: "foo.lan", TTL: 100},
		{Name: "unrelated.lan", TTL: 50, Records: []LocalDomainHost{{Host: "x", Type: "A", Value: "9.9.9.9"}}},
	}
	out := PropagateForkedDomains(domains, "foo.lan")
	for _, d := range out {
		if d.Name == "unrelated.lan" && (d.TTL != 50 || len(d.Records) != 1) {
			t.Errorf("unrelated.lan = %+v, must not be touched by a propagation for a different domain", d)
		}
	}
}

func TestPropagateForkedDomains_DanglingForkedFromLeftUntouched(t *testing.T) {
	domains := []LocalDomain{
		{Name: "orphan.lan", TTL: 42, ForkedFrom: "deleted.lan", Records: []LocalDomainHost{{Host: "x", Type: "A", Value: "9.9.9.9"}}},
	}
	out := PropagateForkedDomains(domains, "deleted.lan")
	if out[0].TTL != 42 || len(out[0].Records) != 1 {
		t.Errorf("orphan.lan = %+v, a dangling ForkedFrom (parent no longer exists) must leave its content untouched", out[0])
	}
}
