// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsstore

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func heapMB() float64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return float64(m.HeapAlloc) / (1 << 20)
}

// TestScale_Report prints load, commit, snapshot and reopen figures at a chosen size; run it with DNSSTORE_ROWS=250000.
func TestScale_Report(t *testing.T) {
	rows, _ := strconv.Atoi(os.Getenv("DNSSTORE_ROWS"))
	if rows == 0 {
		t.Skip("set DNSSTORE_ROWS to run")
	}
	dir := filepath.Join(t.TempDir(), "s")
	opts := Options{Keys: testKeys(), Create: true, SnapshotBytes: 1 << 40}
	s, err := Open(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	base := heapMB()
	body := make([]byte, 120)
	start := time.Now()
	const per = 1000
	for done := 0; done < rows; done += per {
		b := Batch{Origin: 1, Author: "load"}
		for i := 0; i < per && done+i < rows; i++ {
			var id ID
			binary.BigEndian.PutUint64(id[:8], uint64(done+i)*0x9E3779B97F4A7C15)
			binary.BigEndian.PutUint64(id[8:], uint64(done+i))
			binary.LittleEndian.PutUint64(body, uint64(done+i))
			b.Ops = append(b.Ops, Op{Kind: OpPut, Type: 1, ID: id, Body: append([]byte(nil), body...)})
		}
		if _, err := s.Commit(b); err != nil {
			t.Fatal(err)
		}
	}
	loadDur := time.Since(start)
	used := heapMB() - base
	t.Logf("load %d rows in %v (%.0f rows/s), heap %.1f MiB = %.0f bytes/row", rows, loadDur, float64(rows)/loadDur.Seconds(), used, used*(1<<20)/float64(rows))

	var lat []time.Duration
	for i := 0; i < 200; i++ {
		var id ID
		id[0], id[15] = byte(i), byte(i>>8)
		t0 := time.Now()
		if _, err := s.Commit(Batch{Ops: []Op{{Kind: OpPut, Type: 1, ID: id, Body: body}}}); err != nil {
			t.Fatal(err)
		}
		lat = append(lat, time.Since(t0))
	}
	var sum time.Duration
	var worst time.Duration
	for _, d := range lat {
		sum += d
		worst = max(worst, d)
	}
	t.Logf("single-row commit: mean %v worst %v (real fsync on this disk)", sum/time.Duration(len(lat)), worst)

	t0 := time.Now()
	if err := s.Snapshot(); err != nil {
		t.Fatal(err)
	}
	t.Logf("snapshot write: %v", time.Since(t0))
	t0 = time.Now()
	if err := s.Verify(); err != nil {
		t.Fatal(err)
	}
	t.Logf("verify: %v", time.Since(t0))
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	t.Logf("GC: %d cycles, total pause %v", ms.NumGC, time.Duration(ms.PauseTotalNs))
	_ = s.Close()

	opts.Create = false
	t0 = time.Now()
	s, err = Open(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("reopen from snapshot: %v, %d rows", time.Since(t0), s.View().Len())
	_ = s.Close()
}

func BenchmarkView_Get(b *testing.B) {
	v := genesisView([32]byte{}, 1)
	h := newRowHasher([]byte("k"))
	var ops []Op
	for i := 0; i < 100000; i++ {
		var id ID
		binary.BigEndian.PutUint64(id[:8], uint64(i)*0x9E3779B97F4A7C15)
		ops = append(ops, Op{Kind: OpPut, Type: 1, ID: id, Body: []byte("x")})
	}
	v = v.withOps(ops, 1, 1, [32]byte{}, h)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, ok := v.Get(1, ops[i%len(ops)].ID); !ok {
			b.Fatal("missing")
		}
	}
}
