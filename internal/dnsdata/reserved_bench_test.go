// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsdata

import (
	"fmt"
	"testing"

	"dnshived/internal/dnsanswer"
)

func BenchmarkReservedNames(b *testing.B) {
	for _, n := range []int{1000, 10000} {
		c := benchCluster(0, 0, 50, n)
		b.Run(fmt.Sprintf("reservations=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				ReservedNames(c)
			}
		})
	}
}

func BenchmarkMergeReserved(b *testing.B) {
	for _, n := range []int{1000, 10000} {
		c := benchCluster(0, 0, 50, n)
		names := ReservedNames(c)
		authored := make([]dnsanswer.RR, 0, 100000)
		for i := 0; i < 100000; i++ {
			authored = append(authored, dnsanswer.RR{Owner: fmt.Sprintf("a%d.lan", i), Type: dnsanswer.TypeA, TTL: 300, RData: []byte{10, 1, byte(i >> 8), byte(i)}})
		}
		b.Run(fmt.Sprintf("names=%d", len(names)), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				spec := &dnsanswer.Spec{RRs: append(make([]dnsanswer.RR, 0, len(authored)+2*len(names)), authored...)}
				MergeReserved(spec, names, 300)
			}
		})
	}
}
