// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsstore

import (
	"bufio"
	"bytes"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"dnshived/internal/dnsstore/vfs/faultfs"
)

func FuzzDecodeBatch(f *testing.F) {
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 8; i++ {
		b := randBatch(r, 10)
		p, _ := encodeBatch(&b)
		f.Add(p)
	}
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xFF}, 64))
	f.Fuzz(func(t *testing.T, p []byte) {
		b, err := decodeBatch(p)
		if err != nil {
			return
		}
		if len(b.Ops) == 0 || len(b.Ops) > MaxOps {
			t.Fatalf("decoded %d operations", len(b.Ops))
		}
		if _, err := encodeBatch(&b); err != nil {
			t.Fatalf("a decoded batch must encode again: %v", err)
		}
	})
}

func FuzzReadRecord(f *testing.F) {
	rec := record{typ: recBatch, keyEpoch: 1, term: 1, rev: 1, payload: []byte("payload")}
	f.Add(encodeRecord(&rec))
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF, 1, 2, 3})
	f.Fuzz(func(t *testing.T, p []byte) {
		br := bufio.NewReader(bytes.NewReader(p))
		off := int64(0)
		for i := 0; i < 8; i++ {
			_, n, err := readRecord(br, int64(len(p))-off)
			if err != nil {
				return
			}
			off += n
		}
	})
}

func FuzzDecodeHeader(f *testing.F) {
	f.Add(encodeHeader(header{ftype: ftLog, major: verMajor, storeID: ID{1}, firstRev: 5}))
	f.Add([]byte("short"))
	f.Fuzz(func(t *testing.T, p []byte) {
		_, _ = decodeHeader(p, "fuzz")
	})
}

func FuzzLoadSnapshot(f *testing.F) {
	fs := faultfs.New(1)
	m := buildStoreForFuzz(f, fs)
	_ = m
	for _, n := range fs.Names(testDir) {
		if _, ok := parseName(n, "snap-", ".snap"); ok {
			raw, _ := fs.Raw(filepath.Join(testDir, n))
			f.Add(raw)
		}
	}
	f.Add([]byte{})
	id := ID{}
	f.Fuzz(func(t *testing.T, p []byte) {
		fs := faultfs.New(2)
		file, err := fs.OpenFile("/snap", os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = file.WriteAt(p, 0)
		_, _ = loadSnapshot(fs, "/snap", id, testKeys())
	})
}

func buildStoreForFuzz(tb testing.TB, fs *faultfs.FS) model {
	tb.Helper()
	s, err := Open(testDir, Options{FS: fs, Keys: testKeys(), Create: true, SegmentSize: 4096, SnapshotBytes: 1 << 40, StoreID: ID{}})
	if err != nil {
		tb.Fatal(err)
	}
	r := rand.New(rand.NewSource(5))
	m := model{}
	for i := 0; i < 30; i++ {
		b := randBatch(r, 15)
		if _, err := s.Commit(b); err != nil {
			tb.Fatal(err)
		}
		m.apply(b)
	}
	if err := s.Snapshot(); err != nil {
		tb.Fatal(err)
	}
	_ = s.Close()
	return m
}
