// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsfeed

import (
	"fmt"
	"testing"
	"time"

	"dnshived/internal/dnsanswer"
)

func bigBlob(b *testing.B, hosts int) []byte {
	b.Helper()
	rrs := make([]dnsanswer.RR, 0, hosts)
	for i := 0; i < hosts; i++ {
		rrs = append(rrs, rr(b, fmt.Sprintf("h%d.example.lan", i), fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255)))
	}
	return blobOf(b, 1, rrs...)
}

func BenchmarkFeedSnapshot(b *testing.B) {
	for _, hosts := range []int{10000, 100000} {
		blob := bigBlob(b, hosts)
		b.Run(fmt.Sprintf("names=%d", hosts), func(b *testing.B) {
			r := newRig(b, Options{}, ConsumerOptions{})
			b.SetBytes(int64(len(blob)))
			i := 0
			for b.Loop() {
				i++
				if err := r.pub.SetBase(blob); err != nil {
					b.Fatal(err)
				}
				r.next(func(e viewEvent) bool { return e.info.Epoch == uint64(i) })
			}
		})
	}
}

func BenchmarkFeedChange(b *testing.B) {
	r := newRig(b, Options{MaxRingBytes: 1 << 40}, ConsumerOptions{})
	if err := r.pub.SetBase(bigBlob(b, 100000)); err != nil {
		b.Fatal(err)
	}
	r.next(nil)
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		i++
		name := fmt.Sprintf("n%d.example.lan", i%200)
		seq, err := r.pub.Publish(uint32(i+1), []dnsanswer.Change{{Owner: name, RRs: []dnsanswer.RR{rr(b, name, "10.9.0.1")}}})
		if err != nil {
			b.Fatal(err)
		}
		r.next(func(e viewEvent) bool { return e.info.Seq == seq })
	}
	b.ReportMetric(float64(time.Duration(b.Elapsed()))/float64(b.N)/1e3, "us/change")
}
