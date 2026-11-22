// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsanswer

import (
	"fmt"
	"testing"
)

func benchTable(b *testing.B, hosts int) *Table {
	b.Helper()
	bl := NewBuilder()
	if err := bl.AddZone("example.lan", false); err != nil {
		b.Fatal(err)
	}
	for i := 0; i < hosts; i++ {
		rd, _ := RDataA(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255))
		if err := bl.Add(RR{Owner: fmt.Sprintf("h%d.example.lan", i), Type: TypeA, TTL: 300, RData: rd}); err != nil {
			b.Fatal(err)
		}
	}
	rd, _ := RDataA("10.9.9.9")
	if err := bl.Add(RR{Owner: "*.apps.example.lan", Type: TypeA, TTL: 300, RData: rd}); err != nil {
		b.Fatal(err)
	}
	t, err := bl.Build(1, 60)
	if err != nil {
		b.Fatal(err)
	}
	return t
}

func BenchmarkRespond(b *testing.B) {
	t := benchTable(b, 100000)
	cases := []struct {
		name string
		q    []byte
	}{
		{"hit", mkQuery("h50000.example.lan", TypeA, true, 1232)},
		{"hit-other-type", mkQuery("h50000.example.lan", TypeAAAA, false, 0)},
		{"nxdomain", mkQuery("nothere.example.lan", TypeA, true, 1232)},
		{"wildcard", mkQuery("x.apps.example.lan", TypeA, false, 0)},
		{"forward", mkQuery("www.example.com", TypeA, false, 0)},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			buf := make([]byte, 0, 1500)
			b.ReportAllocs()
			for b.Loop() {
				t.Respond(c.q, buf, false)
			}
		})
	}
}
