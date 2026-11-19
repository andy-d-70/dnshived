// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package config

import "testing"

func dnsDHCPHashFixture() Cluster {
	return Cluster{
		PSK: "k",
		Scopes: map[string]ScopeConfig{"office": {
			VIP: "10.0.0.254/24", NodeIP: "10.0.0.22/24", Gateway: "10.0.0.1", DHCPRange: [2]string{"10.0.0.100", "10.0.0.200"},
			Reservations: []Reservation{{MAC: "aa:bb:cc:00:00:01", IP: "10.0.0.50", Hostname: "nas"}},
			DNSRecords:   []DNSRecord{{Name: "x.lan.", Type: "A", Value: "10.0.0.7"}},
		}},
		LocalDomains:       []LocalDomain{{Name: "office.lan", Records: []LocalDomainHost{{Host: "nas", Type: "A", Value: "10.0.0.50"}}}},
		GlobalDNSRecords:   []DNSRecord{{Name: "g.lan.", Type: "A", Value: "10.0.0.8"}},
		DefaultDHCPOptions: []string{"option:42,192.0.2.1"},
	}
}

// The configuration sanity check compares these hashes between the nodes, so
// every kind of replicated DNS and DHCP data must change them, and a node's own
// address must not.
func TestConfigDocumentHashes_CoverTheReplicatedDNSAndDHCPData(t *testing.T) {
	base := dnsDHCPHashFixture()
	v1, v2 := base.ConfigDocumentHashes()
	if v1 == "" || v2 == "" {
		t.Fatal("hashes are empty")
	}
	changes := map[string]func(c *Cluster){
		"a new reservation": func(c *Cluster) {
			s := c.Scopes["office"]
			s.Reservations = append(s.Reservations, Reservation{MAC: "aa:bb:cc:00:00:02", IP: "10.0.0.51"})
			c.Scopes["office"] = s
		},
		"a reservation address": func(c *Cluster) {
			s := c.Scopes["office"]
			s.Reservations = append([]Reservation(nil), s.Reservations...)
			s.Reservations[0].IP = "10.0.0.60"
			c.Scopes["office"] = s
		},
		"a reservation extra name": func(c *Cluster) {
			s := c.Scopes["office"]
			s.Reservations = append([]Reservation(nil), s.Reservations...)
			s.Reservations[0].Names = []string{"files"}
			c.Scopes["office"] = s
		},
		"a reservation client id": func(c *Cluster) {
			s := c.Scopes["office"]
			s.Reservations = append([]Reservation(nil), s.Reservations...)
			s.Reservations[0].ClientID = "01:aa"
			c.Scopes["office"] = s
		},
		"a scope DNS record": func(c *Cluster) {
			s := c.Scopes["office"]
			s.DNSRecords = append(append([]DNSRecord(nil), s.DNSRecords...), DNSRecord{Name: "y.lan.", Type: "A", Value: "10.0.0.9"})
			c.Scopes["office"] = s
		},
		"a domain record": func(c *Cluster) {
			c.LocalDomains = []LocalDomain{{Name: "office.lan", Records: []LocalDomainHost{{Host: "nas", Type: "A", Value: "10.0.0.51"}}}}
		},
		"a new domain": func(c *Cluster) {
			c.LocalDomains = append(append([]LocalDomain(nil), c.LocalDomains...), LocalDomain{Name: "av.lan"})
		},
		"a domain link": func(c *Cluster) {
			c.LocalDomains = append(append([]LocalDomain(nil), c.LocalDomains...), LocalDomain{Name: "link.lan", ForkedFrom: "office.lan"})
		},
		"a domain TTL": func(c *Cluster) {
			c.LocalDomains = []LocalDomain{{Name: "office.lan", TTL: 60, Records: c.LocalDomains[0].Records}}
		},
		"a global record": func(c *Cluster) {
			c.GlobalDNSRecords = append(append([]DNSRecord(nil), c.GlobalDNSRecords...), DNSRecord{Name: "h.lan.", Type: "A", Value: "10.0.0.10"})
		},
		"a default DHCP option": func(c *Cluster) { c.DefaultDHCPOptions = []string{"option:42,192.0.2.2"} },
		"the scope DHCP range":  func(c *Cluster) { s := c.Scopes["office"]; s.DHCPRange[1] = "10.0.0.220"; c.Scopes["office"] = s },
		"the client DNS server": func(c *Cluster) { s := c.Scopes["office"]; s.ClientDNSServer = "10.0.0.2"; c.Scopes["office"] = s },
	}
	for name, mutate := range changes {
		t.Run(name, func(t *testing.T) {
			c := dnsDHCPHashFixture()
			mutate(&c)
			n1, n2 := c.ConfigDocumentHashes()
			if n1 == v1 || n2 == v2 {
				t.Errorf("%s does not change the hashes: v1 %v v2 %v", name, n1 == v1, n2 == v2)
			}
		})
	}
	own := dnsDHCPHashFixture()
	s := own.Scopes["office"]
	s.NodeIP = "10.0.0.99/24"
	own.Scopes["office"] = s
	if a, b := own.ConfigDocumentHashes(); a != v1 || b != v2 {
		t.Error("a node's own address must not change the hashes, or every node would differ from its peers")
	}
}
