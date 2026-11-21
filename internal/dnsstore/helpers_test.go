// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsstore

import (
	"fmt"
	"math/rand"
	"testing"

	"dnshived/internal/dnsstore/vfs"
)

const testDir = "/store"

func testKeys() Keys {
	return StaticKeys{Cur: 1, Epochs: map[uint32][]byte{
		1: []byte("0123456789abcdef0123456789abcdef"),
		2: []byte("fedcba9876543210fedcba9876543210"),
	}}
}

func openTest(t testing.TB, fs vfs.FS, create bool, segSize int64) *Store {
	t.Helper()
	s, err := Open(testDir, Options{FS: fs, Keys: testKeys(), Create: create, SegmentSize: segSize, SnapshotBytes: 1 << 40})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return s
}

type mkey struct {
	typ uint8
	id  ID
}

type model map[mkey]string

func (m model) clone() model {
	out := make(model, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func (m model) apply(b Batch) {
	for _, op := range b.Ops {
		k := mkey{op.Type, op.ID}
		if op.Kind == OpPut {
			m[k] = string(op.Body)
		} else {
			delete(m, k)
		}
	}
}

func idN(n int) ID {
	var id ID
	r := rand.New(rand.NewSource(int64(n)))
	r.Read(id[:])
	return id
}

func randBatch(r *rand.Rand, pool int) Batch {
	b := Batch{Origin: 1, Author: "tester", TimeMs: int64(r.Intn(1 << 20))}
	for i, n := 0, 1+r.Intn(8); i < n; i++ {
		op := Op{Kind: OpPut, Type: uint8(1 + r.Intn(3)), ID: idN(r.Intn(pool))}
		if r.Intn(4) == 0 {
			op.Kind = OpDel
		} else {
			op.Body = []byte(fmt.Sprintf("body-%d-%d", r.Intn(1000), r.Intn(1000)))
		}
		b.Ops = append(b.Ops, op)
	}
	return b
}

func checkModel(t testing.TB, v *View, m model) {
	t.Helper()
	if v.Len() != len(m) {
		t.Fatalf("rows: store %d, model %d", v.Len(), len(m))
	}
	for k, want := range m {
		got, _, ok := v.Get(k.typ, k.id)
		if !ok || string(got) != want {
			t.Fatalf("row %v: store %q ok=%v, model %q", k, got, ok, want)
		}
	}
	seen := 0
	for typ := uint8(1); typ <= 3; typ++ {
		v.Range(typ, func(id ID, rev uint64, body []byte) bool {
			if want, ok := m[mkey{typ, id}]; !ok || want != string(body) {
				t.Fatalf("range returned unexpected row %v", id)
			}
			seen++
			return true
		})
	}
	if seen != len(m) {
		t.Fatalf("range saw %d rows, model has %d", seen, len(m))
	}
}
