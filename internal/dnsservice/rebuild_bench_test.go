// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsservice

import (
	"fmt"
	"net/netip"
	"testing"

	"dnshived/internal/dnsdata"
	"dnshived/internal/dnsfeed"
	"dnshived/internal/dnsstore"
)

func BenchmarkRebuildOneLeaseChange(b *testing.B) {
	for _, hosts := range []int{10000, 50000} {
		for _, feed := range []bool{false, true} {
			b.Run(fmt.Sprintf("hosts=%d/feed=%v", hosts, feed), func(b *testing.B) {
				var pub *dnsfeed.Publisher
				if feed {
					pub = dnsfeed.NewPublisher(dnsfeed.Options{MaxRingBytes: 1 << 40})
				}
				r := openRigWith(b, b.TempDir(), 0, func(o *Options) { o.Feed = pub })
				ops := make([]dnsstore.Op, 0, hosts)
				for i := 0; i < hosts; i++ {
					h := dnsdata.Host{Label: fmt.Sprintf("h%d", i), Domains: []string{"example.lan"}, Addrs: []dnsdata.Addr{{IP: netip.MustParseAddr(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255))}}}
					var id dnsstore.ID
					copy(id[:], fmt.Sprintf("%016d", i))
					ops = append(ops, dnsstore.Op{Kind: dnsstore.OpPut, Type: dnsdata.TypeHost, ID: id, Body: h.Encode()})
				}
				if _, err := r.svc.store.Commit(dnsstore.Batch{Origin: OriginAPI, Ops: ops}); err != nil {
					b.Fatal(err)
				}
				if err := r.svc.Rebuild(true); err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				i := 0
				for b.Loop() {
					i++
					leases := []dnsdata.LeaseName{{Name: fmt.Sprintf("l%d.example.lan", i%100), IP: netip.MustParseAddr("10.200.0.1"), MAC: "02:00:00:00:00:01", LeasedAt: int64(i)}}
					r.leases.Store(&leases)
					if err := r.svc.Rebuild(false); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
