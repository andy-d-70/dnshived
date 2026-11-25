// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsverify

import (
	"fmt"
	"testing"

	"dnshived/internal/config"
)

// largeCluster approaches the large lab corpus: 500 local domains with 100,000 records and 102 scopes with 10,200
// reservations.
func largeCluster() *config.Cluster {
	c := &config.Cluster{Scopes: map[string]config.ScopeConfig{}}
	for d := range 500 {
		ld := config.LocalDomain{Name: fmt.Sprintf("d%d.lan", d), TTL: 300}
		for h := range 200 {
			n := d*200 + h
			ld.Records = append(ld.Records, config.LocalDomainHost{Host: fmt.Sprintf("h%d", h), Type: "A", Value: fmt.Sprintf("10.%d.%d.%d", 64+n>>16, n>>8&255, n&255)})
		}
		c.LocalDomains = append(c.LocalDomains, ld)
	}
	for s := range 102 {
		sc := config.ScopeConfig{}
		for r := range 100 {
			sc.Reservations = append(sc.Reservations, config.Reservation{IP: fmt.Sprintf("172.16.%d.%d", s, r+1), Hostname: fmt.Sprintf("r%d-%d", s, r), Names: []string{fmt.Sprintf("x%d-%d.d0.lan", s, r)}})
		}
		c.Scopes[fmt.Sprintf("scope%03d", s)] = sc
	}
	return c
}

func BenchmarkRun(b *testing.B) {
	r := newRig(b, largeCluster())
	r.in.Leases = nil
	r.publish()
	if res := r.run(); !check(b, res, CheckAnswers).OK || !check(b, res, CheckRows).OK {
		b.Fatalf("the large corpus must verify green: %+v", res.Checks[:2])
	}
	b.ReportAllocs()
	for b.Loop() {
		Run(r.in)
	}
}
