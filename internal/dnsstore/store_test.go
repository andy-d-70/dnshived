// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsstore

import (
	"errors"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"dnshived/internal/dnsstore/vfs"
	"dnshived/internal/dnsstore/vfs/faultfs"
)

func putBatch(n int, body string) Batch {
	return Batch{Origin: 1, Author: "t", Ops: []Op{{Kind: OpPut, Type: 1, ID: idN(n), Body: []byte(body)}}}
}

func TestOpen_NoStoreWithoutCreate(t *testing.T) {
	_, err := Open(testDir, Options{FS: faultfs.New(1), Keys: testKeys()})
	if !errors.Is(err, ErrNoStore) {
		t.Fatalf("got %v, want ErrNoStore", err)
	}
}

func TestStore_CommitReopenAndVerify(t *testing.T) {
	fs := faultfs.New(1)
	s := openTest(t, fs, true, 4096)
	m := model{}
	for i := 0; i < 50; i++ {
		b := putBatch(i%7, "v"+string(rune('a'+i%26)))
		rev, err := s.Commit(b)
		if err != nil || rev != uint64(i+1) {
			t.Fatalf("commit %d: rev %d err %v", i, rev, err)
		}
		m.apply(b)
	}
	if err := s.Verify(); err != nil {
		t.Fatal(err)
	}
	chain := s.View().Chain()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openTest(t, fs, false, 4096)
	defer s.Close()
	if s.View().Rev() != 50 || s.View().Chain() != chain {
		t.Fatalf("after reopen: rev %d", s.View().Rev())
	}
	checkModel(t, s.View(), m)
}

func TestStore_SnapshotPrunesAndReloads(t *testing.T) {
	fs := faultfs.New(2)
	s := openTest(t, fs, true, 700)
	m := model{}
	r := rand.New(rand.NewSource(2))
	for i := 0; i < 120; i++ {
		b := randBatch(r, 30)
		if _, err := s.Commit(b); err != nil {
			t.Fatal(err)
		}
		m.apply(b)
		if i%25 == 24 {
			if err := s.Snapshot(); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := s.Snapshot(); err != nil {
		t.Fatal(err)
	}
	snaps := 0
	for _, n := range fs.Names(testDir) {
		if _, ok := parseName(n, "snap-", ".snap"); ok {
			snaps++
		}
	}
	if snaps != keepSnapshots {
		t.Fatalf("kept %d snapshots, want %d", snaps, keepSnapshots)
	}
	rev := s.View().Rev()
	_ = s.Close()
	s = openTest(t, fs, false, 700)
	defer s.Close()
	if s.View().Rev() != rev {
		t.Fatalf("rev %d after reopen, want %d", s.View().Rev(), rev)
	}
	checkModel(t, s.View(), m)
	if err := s.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestStore_RotateKeepsDataAndChain(t *testing.T) {
	fs := faultfs.New(3)
	s := openTest(t, fs, true, 2048)
	m := model{}
	for i := 0; i < 10; i++ {
		b := putBatch(i, "x")
		_, _ = s.Commit(b)
		m.apply(b)
	}
	if _, err := s.Rotate(2); err != nil {
		t.Fatal(err)
	}
	if s.View().KeyEpoch() != 2 {
		t.Fatal("epoch did not change")
	}
	for i := 10; i < 20; i++ {
		b := putBatch(i, "y")
		if _, err := s.Commit(b); err != nil {
			t.Fatal(err)
		}
		m.apply(b)
	}
	if err := s.Verify(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Rotate(2); !errors.Is(err, ErrKey) {
		t.Fatalf("rotating to the same epoch: %v", err)
	}
	_ = s.Snapshot()
	_ = s.Close()
	s = openTest(t, fs, false, 2048)
	defer s.Close()
	if s.View().KeyEpoch() != 2 || s.View().Rev() != 21 {
		t.Fatalf("epoch %d rev %d", s.View().KeyEpoch(), s.View().Rev())
	}
	checkModel(t, s.View(), m)
}

func TestStore_RecordsStreamsFromRevision(t *testing.T) {
	fs := faultfs.New(4)
	s := openTest(t, fs, true, 800)
	defer s.Close()
	for i := 0; i < 40; i++ {
		_, _ = s.Commit(putBatch(i, "r"))
	}
	var revs []uint64
	if err := s.Records(15, func(r Record) error { revs = append(revs, r.Rev); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(revs) != 26 || revs[0] != 15 || revs[25] != 40 {
		t.Fatalf("got %d records %v", len(revs), revs)
	}
	for i := 0; i < 40; i++ {
		_, _ = s.Commit(putBatch(i, "s"))
	}
	if err := s.Snapshot(); err != nil {
		t.Fatal(err)
	}
	if err := s.Snapshot(); err != nil {
		t.Fatal(err)
	}
	_, _ = s.Commit(putBatch(1, "t"))
	_ = s.Snapshot()
	if err := s.Records(1, func(Record) error { return nil }); !errors.Is(err, ErrGap) {
		t.Fatalf("got %v, want ErrGap once the old log was pruned", err)
	}
}

func TestStore_SyncErrorFailsTheStore(t *testing.T) {
	fs := faultfs.New(5)
	s := openTest(t, fs, true, 4096)
	defer s.Close()
	if _, err := s.Commit(putBatch(1, "a")); err != nil {
		t.Fatal(err)
	}
	fs.InjectSyncError(1)
	if _, err := s.Commit(putBatch(2, "b")); !errors.Is(err, ErrFailed) {
		t.Fatalf("got %v, want ErrFailed", err)
	}
	if _, err := s.Commit(putBatch(3, "c")); !errors.Is(err, ErrFailed) {
		t.Fatalf("a later commit must stay refused, got %v", err)
	}
}

func TestStore_SecondOpenIsLocked(t *testing.T) {
	fs := faultfs.New(6)
	s := openTest(t, fs, true, 4096)
	defer s.Close()
	if _, err := Open(testDir, Options{FS: fs, Keys: testKeys()}); !errors.Is(err, vfs.ErrLocked) {
		t.Fatalf("got %v, want ErrLocked", err)
	}
}

func TestStore_WrongStoreID(t *testing.T) {
	fs := faultfs.New(7)
	s := openTest(t, fs, true, 4096)
	_ = s.Close()
	_, err := Open(testDir, Options{FS: fs, Keys: testKeys(), StoreID: ID{1}})
	if !errors.Is(err, ErrStoreID) {
		t.Fatalf("got %v, want ErrStoreID", err)
	}
}

func TestStore_BatchLimits(t *testing.T) {
	fs := faultfs.New(8)
	s := openTest(t, fs, true, 1<<20)
	defer s.Close()
	big := Batch{Ops: []Op{{Kind: OpPut, Type: 1, Body: make([]byte, MaxRow+1)}}}
	if _, err := s.Commit(big); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v, want ErrTooLarge", err)
	}
	if _, err := s.Commit(Batch{}); !errors.Is(err, ErrBadBatch) {
		t.Fatalf("empty batch: %v", err)
	}
	if _, err := s.Commit(Batch{Ops: []Op{{Kind: OpDel, Type: 1, Body: []byte("x")}}}); !errors.Is(err, ErrBadBatch) {
		t.Fatalf("delete with body: %v", err)
	}
	if s.View().Rev() != 0 {
		t.Fatal("a rejected batch must not change the store")
	}
}

func TestStore_TombstonesPrune(t *testing.T) {
	fs := faultfs.New(9)
	s := openTest(t, fs, true, 1<<20)
	defer s.Close()
	_, _ = s.Commit(putBatch(1, "a"))
	_, _ = s.Commit(Batch{Ops: []Op{{Kind: OpDel, Type: 1, ID: idN(1)}}})
	if _, ok := s.View().Tombstone(1, idN(1)); !ok {
		t.Fatal("tombstone missing")
	}
	s.PruneTombstones(2)
	if _, ok := s.View().Tombstone(1, idN(1)); ok || s.View().Tombstones() != 0 {
		t.Fatal("tombstone not pruned")
	}
	if err := s.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestStore_RealFilesystem(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "dnsstore")
	opts := Options{Keys: testKeys(), Create: true, SegmentSize: 8192, SnapshotBytes: 1 << 40}
	s, err := Open(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	m := model{}
	r := rand.New(rand.NewSource(10))
	for i := 0; i < 200; i++ {
		b := randBatch(r, 40)
		if _, err := s.Commit(b); err != nil {
			t.Fatal(err)
		}
		m.apply(b)
	}
	if err := s.Snapshot(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		b := randBatch(r, 40)
		_, _ = s.Commit(b)
		m.apply(b)
	}
	if _, err := Open(dir, opts); !errors.Is(err, vfs.ErrLocked) {
		t.Fatalf("second open: %v", err)
	}
	_ = s.Close()
	opts.Create = false
	s, err = Open(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	checkModel(t, s.View(), m)
	entries, _ := os.ReadDir(dir)
	found := false
	for _, e := range entries {
		if _, ok := parseName(e.Name(), "seg-", ".log"); !ok {
			continue
		}
		st, err := e.Info()
		if err != nil || st.Size() < 8192 || st.Mode().Perm() != 0o600 {
			t.Fatalf("segment %s size %d mode %v err %v, want preallocated and 0600", e.Name(), st.Size(), st.Mode().Perm(), err)
		}
		found = true
	}
	if !found {
		t.Fatal("no segment file")
	}
}

func TestModel_RandomOperationsWithRestarts(t *testing.T) {
	for seed := int64(1); seed <= 5; seed++ {
		fs := faultfs.New(seed)
		r := rand.New(rand.NewSource(seed))
		s := openTest(t, fs, true, 900)
		m := model{}
		epoch := uint32(1)
		for i := 0; i < 300; i++ {
			switch x := r.Intn(100); {
			case x < 80:
				b := randBatch(r, 50)
				if _, err := s.Commit(b); err != nil {
					t.Fatalf("seed %d step %d: %v", seed, i, err)
				}
				m.apply(b)
			case x < 88:
				if err := s.Snapshot(); err != nil {
					t.Fatal(err)
				}
			case x < 96:
				_ = s.Close()
				s = openTest(t, fs, false, 900)
			case x < 98 && epoch == 1:
				if _, err := s.Rotate(2); err != nil {
					t.Fatal(err)
				}
				epoch = 2
			default:
				s.PruneTombstones(s.View().Rev())
			}
			checkModel(t, s.View(), m)
		}
		if err := s.Verify(); err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		_ = s.Close()
	}
}

func TestStore_RefusesWritableDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "open")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	_, err := Open(dir, Options{Keys: testKeys(), Create: true})
	if !errors.Is(err, ErrPermissions) {
		t.Fatalf("got %v, want ErrPermissions", err)
	}
}
