// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsanswer

import (
	"fmt"
	"testing"
)

func benchLive(b *testing.B, hosts, changed int) *Live {
	b.Helper()
	base := benchTable(b, hosts)
	live := NewLive(base, []Zone{{Name: "example.lan"}}, 0)
	ch := make([]Change, 0, changed)
	for i := 0; i < changed; i++ {
		o := fmt.Sprintf("n%d.example.lan", i)
		ch = append(ch, Change{Owner: o, RRs: []RR{deltaRR(o, TypeA, fmt.Sprintf("10.7.%d.%d", i>>8&255, i&255))}})
	}
	if changed > 0 {
		if _, err := live.Apply(2, ch); err != nil {
			b.Fatal(err)
		}
	}
	return live
}

func BenchmarkRespondOverlay(b *testing.B) {
	for _, changed := range []int{0, 1000, 10000} {
		live := benchLive(b, 100000, changed)
		for _, c := range []struct {
			name string
			q    []byte
		}{
			{"base-hit", mkQuery("h50000.example.lan", TypeA, true, 1232)},
			{"overlay-hit", mkQuery("n5.example.lan", TypeA, true, 1232)},
			{"nxdomain", mkQuery("nothere.example.lan", TypeA, true, 1232)},
		} {
			b.Run(fmt.Sprintf("changed=%d/%s", changed, c.name), func(b *testing.B) {
				buf := make([]byte, 0, 1500)
				b.ReportAllocs()
				for b.Loop() {
					live.Table().Respond(c.q, buf, false)
				}
			})
		}
	}
}

func BenchmarkLiveApply(b *testing.B) {
	for _, changed := range []int{0, 1000, 10000} {
		live := benchLive(b, 100000, changed)
		b.Run(fmt.Sprintf("alreadyChanged=%d", changed), func(b *testing.B) {
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				i++
				o := fmt.Sprintf("n%d.example.lan", i%(changed+1))
				if _, err := live.Apply(uint32(i+3), []Change{{Owner: o, RRs: []RR{deltaRR(o, TypeA, "10.8.0.1")}}}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
