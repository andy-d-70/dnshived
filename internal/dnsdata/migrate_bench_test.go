// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsdata

import (
	"fmt"
	"testing"

	"dnshived/internal/config"
)

func benchCluster(domains, hostsPerDomain, scopes, reservations int) *config.Cluster {
	c := &config.Cluster{Scopes: map[string]config.ScopeConfig{}}
	for d := 0; d < domains; d++ {
		dom := config.LocalDomain{Name: fmt.Sprintf("d%d.lan", d), TTL: 300}
		for h := 0; h < hostsPerDomain; h++ {
			ip := fmt.Sprintf("10.%d.%d.%d", d%250, h/250%250, h%250+1)
			dom.Records = append(dom.Records,
				config.LocalDomainHost{Host: fmt.Sprintf("h%d", h), Type: "A", Value: ip},
				config.LocalDomainHost{Host: fmt.Sprintf("h%d", h), Type: "TXT", Value: "v=1"})
		}
		if d%3 == 2 {
			dom.ForkedFrom = fmt.Sprintf("d%d.lan", d-1)
			dom.Records = append([]config.LocalDomainHost(nil), c.LocalDomains[d-1].Records...)
		}
		c.LocalDomains = append(c.LocalDomains, dom)
	}
	for s := 0; s < scopes; s++ {
		sc := config.ScopeConfig{}
		for r := 0; r < reservations/scopes; r++ {
			sc.Reservations = append(sc.Reservations, config.Reservation{
				MAC: fmt.Sprintf("02:00:00:%02x:%02x:%02x", s, r>>8, r&255), IP: fmt.Sprintf("172.%d.%d.%d", 16+s%16, r>>8&255, r&255),
				Hostname: fmt.Sprintf("dev%d-%d", s, r), Names: []string{fmt.Sprintf("alt%d-%d.lan", s, r), fmt.Sprintf("x%d-%d", s, r)},
			})
		}
		for r := 0; r < 20; r++ {
			sc.DNSRecords = append(sc.DNSRecords, config.DNSRecord{Name: fmt.Sprintf("svc%d.s%d.lan.", r, s), Type: "A", Value: fmt.Sprintf("192.168.%d.%d", s%250, r+1)})
		}
		c.Scopes[fmt.Sprintf("s%03d", s)] = sc
	}
	return c
}

func BenchmarkMigrateOps(b *testing.B) {
	for _, sz := range []struct{ domains, hosts int }{{10, 100}, {50, 1000}, {100, 2500}} {
		c := benchCluster(sz.domains, sz.hosts, 20, 0)
		b.Run(fmt.Sprintf("records=%d", sz.domains*sz.hosts*2), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				MigrateOps(c)
			}
		})
	}
}
