// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"testing"

	"dnshived/internal/config"
)

func TestDNSRecordsDigest_OnlyDNSRecordsMatter(t *testing.T) {
	base := &config.Cluster{
		GlobalDNSRecords: []config.DNSRecord{{Name: "a.example.lan.", Type: "A", Value: "10.0.0.1"}},
		Scopes:           map[string]config.ScopeConfig{"office": {DNSRecords: []config.DNSRecord{{Name: "b.example.lan.", Type: "A", Value: "10.0.0.2"}}}},
		LocalDomains:     []config.LocalDomain{{Name: "example.lan", Records: []config.LocalDomainHost{{Host: "c", Type: "A", Value: "10.0.0.3"}}}},
	}
	d0 := dnsRecordsDigest(base)
	if dnsRecordsDigest(base) != d0 {
		t.Fatal("the digest must be stable")
	}
	other := *base
	other.PSK = "something else"
	other.Role = "core-9"
	if dnsRecordsDigest(&other) != d0 {
		t.Fatal("a change outside the DNS records must not look like a DNS change")
	}
	for name, mutate := range map[string]func(*config.Cluster){
		"global record": func(c *config.Cluster) { c.GlobalDNSRecords[0].Value = "10.9.9.9" },
		"scope record":  func(c *config.Cluster) { c.Scopes["office"] = config.ScopeConfig{} },
		"domain record": func(c *config.Cluster) { c.LocalDomains[0].Records[0].Host = "z" },
	} {
		c := *base
		c.GlobalDNSRecords = append([]config.DNSRecord(nil), base.GlobalDNSRecords...)
		c.Scopes = map[string]config.ScopeConfig{"office": base.Scopes["office"]}
		c.LocalDomains = []config.LocalDomain{{Name: "example.lan", Records: append([]config.LocalDomainHost(nil), base.LocalDomains[0].Records...)}}
		mutate(&c)
		if dnsRecordsDigest(&c) == d0 {
			t.Errorf("%s: a change to the DNS records must change the digest", name)
		}
	}
}

func TestDNSConfigFrozen_OffWithoutAStore(t *testing.T) {
	if dnsConfigFrozen() {
		t.Fatal("with no DNS store running nothing is frozen")
	}
}
