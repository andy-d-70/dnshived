// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package config

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestClone_EqualButIndependent(t *testing.T) {
	c := splitFixture()
	c.Peers = []string{"10.0.0.2:9443"}
	c.TrustedHosts = []string{"10.0.0.2"}
	c.APITokens = []APIToken{{Name: "a", Token: "t", Role: "admin"}}
	c.ParkedScopes = map[string]ScopeConfig{"p": {Parent: "eth1", VLANID: 9, VIP: "192.168.9.1/24"}}
	c.Extra = map[string]json.RawMessage{"future": json.RawMessage(`{"a":[1,2]}`)}
	office := c.Scopes["office"]
	office.NodeIPOverrides = map[string]string{"core-1": "192.168.100.5/24"}
	c.Scopes["office"] = office

	cp := c.Clone()
	if !reflect.DeepEqual(*c, cp) {
		t.Fatal("a clone must equal the original")
	}

	cp.Peers[0] = "changed"
	cp.TrustedHosts = append(cp.TrustedHosts, "x")
	cp.APITokens[0].Name = "changed"
	cp.LocalDomains[0].Records[0].Value = "changed"
	cp.LocalDomains[0].Name = "changed"
	cp.Scopes["office"] = ScopeConfig{}
	cp.Scopes["new"] = ScopeConfig{}
	cp.ParkedScopes["p"] = ScopeConfig{}
	cp.Extra["future"][0] = 'X'
	cp.GlobalDNSRecords[0].Value = "changed"
	cp.Platform.Workers[0] = "changed"
	o := cp.Scopes["office"]
	o.Reservations = nil

	orig := splitFixture()
	if c.Peers[0] != "10.0.0.2:9443" || c.TrustedHosts[0] != "10.0.0.2" || c.APITokens[0].Name != "a" {
		t.Error("slices are shared with the original")
	}
	if c.LocalDomains[0].Records[0].Value == "changed" || c.LocalDomains[0].Name == "changed" {
		t.Error("nested slices are shared with the original")
	}
	if _, ok := c.Scopes["new"]; ok || c.Scopes["office"].Parent != orig.Scopes["office"].Parent {
		t.Error("the scope map is shared with the original")
	}
	if c.ParkedScopes["p"].Parent != "eth1" {
		t.Error("the parked scope map is shared")
	}
	if string(c.Extra["future"]) != `{"a":[1,2]}` {
		t.Errorf("raw JSON bytes are shared: %s", c.Extra["future"])
	}
	if c.GlobalDNSRecords[0].Value == "changed" || c.Platform.Workers[0] == "changed" {
		t.Error("global records or the platform are shared")
	}
	if len(c.Scopes["office"].Reservations) == 0 {
		t.Error("reservations are shared")
	}
	if cp.Scopes["office"].NodeIPOverrides != nil {
		t.Error("the replaced scope should be the empty one")
	}
}

func TestClone_NilsStayNilAndTheDocumentRoundTrips(t *testing.T) {
	var empty Cluster
	cp := empty.Clone()
	if cp.Scopes != nil || cp.Peers != nil || cp.Platform != nil || cp.Extra != nil {
		t.Error("nil maps, slices and pointers must stay nil")
	}
	c := splitFixture()
	a, _ := json.Marshal(c)
	b, _ := json.Marshal(c.Clone())
	if string(a) != string(b) {
		t.Error("a clone marshals to the same document")
	}
}

func BenchmarkClone(b *testing.B) {
	c := *bigCluster(300, 150)
	b.ReportAllocs()
	for b.Loop() {
		_ = c.Clone()
	}
}
