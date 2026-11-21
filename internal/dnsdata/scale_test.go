// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsdata

import (
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"

	"dnshived/internal/dnsanswer"
	"dnshived/internal/dnsstore"
)

func heapMB() float64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return float64(m.HeapAlloc) / (1 << 20)
}

// TestScale_Report prints compile, build and lookup figures; run it with DNSDATA_HOSTS=250000.
func TestScale_Report(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("DNSDATA_HOSTS"))
	if n == 0 {
		t.Skip("set DNSDATA_HOSTS to run")
	}
	s := newStore(t)
	t0 := time.Now()
	for done := 0; done < n; done += 2000 {
		var ops []dnsstore.Op
		for i := done; i < done+2000 && i < n; i++ {
			a := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
			ops = append(ops, putHost(i+1, Host{Label: fmt.Sprintf("host-%d", i), Domains: []string{"example.lan"}, Addrs: []Addr{{IP: a, PTR: true}}}))
		}
		commit(t, s, ops...)
	}
	t.Logf("store load of %d hosts: %v", n, time.Since(t0))
	base := heapMB()
	t0 = time.Now()
	spec, rep := Compile(s.View(), cfg)
	t.Logf("compile: %v (%d RRs, %d errors)", time.Since(t0), len(spec.RRs), len(rep.Errors))
	t0 = time.Now()
	tb, err := spec.Build()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("table build: %v, %d names, %d records", time.Since(t0), tb.Names(), tb.Records())
	spec = nil
	t.Logf("table heap: %.1f MiB (store views excluded: %.1f MiB before)", heapMB()-base, base)
	q := []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range []string{"host-123456", "example", "lan"} {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0, 0, 1, 0, 1)
	buf := make([]byte, 0, 1500)
	const loops = 2_000_000
	t0 = time.Now()
	for i := 0; i < loops; i++ {
		tb.Respond(q, buf, false)
	}
	d := time.Since(t0)
	t.Logf("Respond: %v per query (%.0f queries/s on one core)", d/loops, float64(loops)/d.Seconds())
	_ = dnsanswer.TypeA
}
