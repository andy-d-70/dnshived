// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsstore

import (
	"errors"
	"hash/crc32"
	"math/rand"
	"path/filepath"
	"testing"

	"dnshived/internal/dnsstore/vfs/faultfs"
)

func buildStore(t *testing.T, fs *faultfs.FS, n int, snapEvery int) model {
	t.Helper()
	s := openTest(t, fs, true, 700)
	r := rand.New(rand.NewSource(77))
	m := model{}
	for i := 0; i < n; i++ {
		b := randBatch(r, 20)
		if _, err := s.Commit(b); err != nil {
			t.Fatal(err)
		}
		m.apply(b)
		if snapEvery > 0 && i%snapEvery == snapEvery-1 {
			if err := s.Snapshot(); err != nil {
				t.Fatal(err)
			}
		}
	}
	_ = s.Close()
	return m
}

func names(fs *faultfs.FS, prefix, suffix string) []string {
	var out []string
	for _, n := range fs.Names(testDir) {
		if _, ok := parseName(n, prefix, suffix); ok {
			out = append(out, n)
		}
	}
	return out
}

func TestCorrupt_DamagedRecordInEarlierSegment(t *testing.T) {
	fs := faultfs.New(1)
	buildStore(t, fs, 40, 0)
	segs := names(fs, "seg-", ".log")
	if len(segs) < 3 {
		t.Fatalf("only %d segments", len(segs))
	}
	if !fs.Poke(filepath.Join(testDir, segs[0]), headerSize+12, []byte{0xFF, 0xEE}) {
		t.Fatal("poke failed")
	}
	_, err := Open(testDir, scenarioOptions(fs, false))
	var ce *CorruptError
	if !errors.Is(err, ErrCorrupt) || !errors.As(err, &ce) || ce.File == "" {
		t.Fatalf("got %v, want a CorruptError", err)
	}
}

func TestCorrupt_ValidChecksumButTamperedPayload(t *testing.T) {
	fs := faultfs.New(2)
	buildStore(t, fs, 5, 0)
	segs := names(fs, "seg-", ".log")
	path := filepath.Join(testDir, segs[0])
	raw, _ := fs.Raw(path)
	r := headerSize
	n := int(le.Uint32(raw[r:]))
	raw[r+40] ^= 0x01
	le.PutUint32(raw[r+4:], crc32.Checksum(raw[r+8:r+4+n], castagnoli))
	fs.Poke(path, r, raw[r:r+4+n])
	_, err := Open(testDir, scenarioOptions(fs, false))
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("got %v, want ErrCorrupt (chain mismatch)", err)
	}
}

func TestCorrupt_NewestSnapshotFallsBackToOlderOne(t *testing.T) {
	fs := faultfs.New(3)
	m := buildStore(t, fs, 60, 20)
	snaps := names(fs, "snap-", ".snap")
	if len(snaps) != 2 {
		t.Fatalf("%d snapshots", len(snaps))
	}
	newest := filepath.Join(testDir, snaps[1])
	if !fs.Poke(newest, headerSize+40, []byte{0x5A, 0x5A, 0x5A}) {
		t.Fatal("poke failed")
	}
	s, err := Open(testDir, scenarioOptions(fs, false))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	if got := s.Recovery().SkippedSnapshots; len(got) != 1 || got[0] != snaps[1] {
		t.Fatalf("skipped %v", got)
	}
	checkModel(t, s.View(), m)
	if q := names(fs, "snap-", ".snap.corrupt"); len(q) != 1 {
		t.Fatalf("expected the damaged snapshot to be quarantined, found %v", q)
	}
}

func TestCorrupt_TornTailIsTruncated(t *testing.T) {
	fs := faultfs.New(4)
	m := buildStore(t, fs, 12, 0)
	segs := names(fs, "seg-", ".log")
	path := filepath.Join(testDir, segs[len(segs)-1])
	raw, _ := fs.Raw(path)
	off := headerSize
	for {
		n := int(le.Uint32(raw[off:]))
		if n == 0 {
			break
		}
		off += 4 + n
	}
	garbage := []byte{0x80, 0x00, 0x00, 0x00, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	if !fs.Poke(path, off, garbage) {
		t.Fatal("no room for the torn record")
	}
	s, err := Open(testDir, scenarioOptions(fs, false))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	if s.Recovery().TruncatedBytes == 0 {
		t.Fatal("torn tail was not reported")
	}
	checkModel(t, s.View(), m)
	if _, err := s.Commit(putBatch(9, "again")); err != nil {
		t.Fatal(err)
	}
}

func TestCorrupt_MissingMiddleSegment(t *testing.T) {
	fs := faultfs.New(5)
	buildStore(t, fs, 40, 0)
	segs := names(fs, "seg-", ".log")
	if err := fs.Remove(filepath.Join(testDir, segs[1])); err != nil {
		t.Fatal(err)
	}
	_ = fs.SyncDir(testDir)
	_, err := Open(testDir, scenarioOptions(fs, false))
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("got %v, want ErrCorrupt for the gap", err)
	}
}

func TestCorrupt_NewerMajorVersionIsRefused(t *testing.T) {
	fs := faultfs.New(6)
	buildStore(t, fs, 3, 0)
	segs := names(fs, "seg-", ".log")
	path := filepath.Join(testDir, segs[0])
	raw, _ := fs.Raw(path)
	le.PutUint16(raw[6:], 2)
	le.PutUint32(raw[60:], crc32.Checksum(raw[:60], castagnoli))
	fs.Poke(path, 0, raw[:headerSize])
	_, err := Open(testDir, scenarioOptions(fs, false))
	if !errors.Is(err, ErrVersion) {
		t.Fatalf("got %v, want ErrVersion", err)
	}
}

func TestCorrupt_UnknownKeyEpoch(t *testing.T) {
	fs := faultfs.New(7)
	buildStore(t, fs, 3, 0)
	_, err := Open(testDir, Options{FS: fs, Keys: StaticKeys{Cur: 9, Epochs: map[uint32][]byte{9: []byte("k")}}})
	if !errors.Is(err, ErrKey) {
		t.Fatalf("got %v, want ErrKey", err)
	}
}

func TestCorrupt_HalfCreatedLastSegmentIsDropped(t *testing.T) {
	fs := faultfs.New(8)
	m := buildStore(t, fs, 10, 0)
	f, err := fs.OpenFile(filepath.Join(testDir, segName(9999)), 0x42, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteAt([]byte("DHD"), 0)
	_ = fs.SyncDir(testDir)
	s, err := Open(testDir, scenarioOptions(fs, false))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	if s.Recovery().DroppedSegment == "" {
		t.Fatal("the half-created segment was not dropped")
	}
	checkModel(t, s.View(), m)
}
