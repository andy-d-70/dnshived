// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package auditlog

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"dnshived/internal/dnsstore/vfs"
	"dnshived/internal/dnsstore/vfs/faultfs"
)

const testDir = "/audit"

var testKey = []byte("test-key-0123456789abcdef0123456")

func openFS(t *testing.T, fs vfs.FS, segSize int64) *Store {
	t.Helper()
	s, err := Open(testDir, Options{FS: fs, Key: testKey, SegmentSize: segSize})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func entry(n int) StoredEntry {
	var id ID
	copy(id[:], fmt.Sprintf("%016d", n))
	id[0] = byte(n * 37)
	return StoredEntry{ID: id, Body: []byte(fmt.Sprintf(`{"ts":"2026-11-27T10:00:00Z","actor":"ann","action":"config.save","summary":"change %d"}`, n))}
}

func entries(from, to int) []StoredEntry {
	var out []StoredEntry
	for i := from; i < to; i++ {
		out = append(out, entry(i))
	}
	return out
}

func held(t *testing.T, s *Store) map[ID]string {
	t.Helper()
	out := map[ID]string{}
	if err := s.Each(func(id ID, body []byte) error {
		if _, dup := out[id]; dup {
			return fmt.Errorf("entry %x listed twice", id)
		}
		out[id] = string(body)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(out) != s.Len() {
		t.Fatalf("Each lists %d entries, Len says %d", len(out), s.Len())
	}
	return out
}

func TestStore_AppendIsDurableAndIdempotent(t *testing.T) {
	fs := faultfs.New(1)
	s := openFS(t, fs, minSegSize)
	n, err := s.Append(entries(0, 100))
	if err != nil || n != 100 {
		t.Fatalf("append: %d %v", n, err)
	}
	if n, err := s.Append(entries(50, 120)); err != nil || n != 20 {
		t.Fatalf("an append of held entries adds only the new ones: %d %v", n, err)
	}
	if len(s.segs) < 3 {
		t.Fatalf("small segments roll over: %d", len(s.segs))
	}
	before, hashes := held(t, s), s.Hashes()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	fs.Crash()
	s = openFS(t, fs, minSegSize)
	defer s.Close()
	if got := held(t, s); len(got) != 120 || s.Hashes() != hashes || len(s.Notes()) != 0 {
		t.Fatalf("reopened store: %d entries (want 120), same hashes %v, notes %v", len(got), s.Hashes() == hashes, s.Notes())
	}
	for id, body := range before {
		if b, ok, err := s.Get(id); err != nil || !ok || string(b) != body {
			t.Fatalf("Get %x: %q %v %v", id, b, ok, err)
		}
	}
}

func TestStore_SameEntriesInAnyOrderHaveTheSameHashes(t *testing.T) {
	a := openFS(t, faultfs.New(1), 0)
	b := openFS(t, faultfs.New(2), 0)
	defer a.Close()
	defer b.Close()
	if _, err := a.Append(entries(0, 300)); err != nil {
		t.Fatal(err)
	}
	for i := 299; i >= 0; i-- {
		if _, err := b.Append([]StoredEntry{entry(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if a.Hashes() != b.Hashes() {
		t.Fatal("union of the same entries must give the same hashes")
	}
	if _, err := b.Append([]StoredEntry{entry(1000)}); err != nil {
		t.Fatal(err)
	}
	diff := 0
	ha, hb := a.Hashes(), b.Hashes()
	for i := range ha {
		if ha[i] != hb[i] {
			diff++
			if got := b.IDs(byte(i)); len(got) != len(a.IDs(byte(i)))+1 {
				t.Fatalf("shard %d ids: %d vs %d", i, len(got), len(a.IDs(byte(i))))
			}
		}
	}
	if diff != 1 {
		t.Fatalf("one extra entry changes one shard hash: %d", diff)
	}
}

func TestStore_RefusesInvalidEntries(t *testing.T) {
	s := openFS(t, faultfs.New(1), 0)
	defer s.Close()
	for _, body := range [][]byte{nil, []byte("a\nb"), bytes.Repeat([]byte("x"), MaxBody+1)} {
		if _, err := s.Append([]StoredEntry{{ID: ID{1}, Body: body}}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("body of %d bytes: %v", len(body), err)
		}
	}
	if s.Len() != 0 {
		t.Fatal("nothing stored from a refused append")
	}
}

// crashScenario appends in batches and returns the entries acknowledged and those attempted.
func crashScenario(fs *faultfs.FS) (acked, tried map[ID]bool) {
	acked, tried = map[ID]bool{}, map[ID]bool{}
	s, err := Open(testDir, Options{FS: fs, Key: testKey, SegmentSize: minSegSize})
	if err != nil {
		return
	}
	defer s.Close()
	for b := 0; b < 8; b++ {
		batch := entries(b*9, b*9+9)
		for _, e := range batch {
			tried[e.ID] = true
		}
		if _, err := s.Append(batch); err != nil {
			return
		}
		for _, e := range batch {
			acked[e.ID] = true
		}
	}
	return
}

func TestStore_CrashAtEveryOperationKeepsAcknowledgedEntries(t *testing.T) {
	probe := faultfs.New(0)
	crashScenario(probe)
	total := probe.Ops()
	if total < 20 {
		t.Fatalf("scenario made only %d operations", total)
	}
	for n := 1; n <= total; n++ {
		for _, torn := range []bool{false, true} {
			fs := faultfs.New(int64(n))
			fs.SetCrashAt(n, torn)
			acked, tried := crashScenario(fs)
			if !fs.Crashed() {
				continue
			}
			fs.Crash()
			label := fmt.Sprintf("crash at %d torn=%v", n, torn)
			s, err := Open(testDir, Options{FS: fs, Key: testKey, SegmentSize: minSegSize})
			if err != nil {
				t.Fatalf("%s: reopen: %v", label, err)
			}
			got := held(t, s)
			for id := range acked {
				if _, ok := got[id]; !ok {
					t.Fatalf("%s: acknowledged entry %x lost", label, id)
				}
			}
			for id := range got {
				if !tried[id] {
					t.Fatalf("%s: entry %x was never written", label, id)
				}
			}
			if _, err := s.Append([]StoredEntry{entry(9999)}); err != nil {
				t.Fatalf("%s: append after recovery: %v", label, err)
			}
			_ = s.Close()
			s, err = Open(testDir, Options{FS: fs, Key: testKey, SegmentSize: minSegSize})
			if err != nil {
				t.Fatalf("%s: second reopen: %v", label, err)
			}
			if again := held(t, s); len(again) != len(got)+1 {
				t.Fatalf("%s: second reopen holds %d, want %d", label, len(again), len(got)+1)
			}
			_ = s.Close()
		}
	}
}

func TestStore_DamageServesTheVerifiedPartAndChangesNothing(t *testing.T) {
	fs := faultfs.New(3)
	s := openFS(t, fs, minSegSize)
	if _, err := s.Append(entries(0, 120)); err != nil {
		t.Fatal(err)
	}
	first := s.segs[0]
	victim := first.name
	firstCount := 0
	for _, l := range s.index {
		if l.seg == 0 {
			firstCount++
		}
	}
	_ = s.Close()
	path := filepath.Join(testDir, victim)
	raw, _ := fs.Raw(path)
	mid := headerSize + (len(raw)-headerSize)/2
	fs.Poke(path, mid, []byte{raw[mid] ^ 0xff})
	damaged, _ := fs.Raw(path)

	s = openFS(t, fs, minSegSize)
	defer s.Close()
	got := held(t, s)
	if len(got) >= 120 || len(got) <= 120-firstCount {
		t.Fatalf("the verified records before the damage stay served, the rest not: %d of 120 (first segment %d)", len(got), firstCount)
	}
	if len(s.Notes()) != 1 {
		t.Fatalf("the damage is reported: %v", s.Notes())
	}
	if now, _ := fs.Raw(path); !bytes.Equal(now, damaged) {
		t.Fatal("the damaged segment is kept exactly as it was")
	}
	if n, err := s.Append(entries(0, 120)); err != nil || n != 120-len(got) {
		t.Fatalf("the missing entries can be filled in again (from a peer): %d %v", n, err)
	}
}

func TestStore_GarbageTailIsKeptAndNewEntriesGoToANewSegment(t *testing.T) {
	fs := faultfs.New(4)
	s := openFS(t, fs, 0)
	if _, err := s.Append(entries(0, 10)); err != nil {
		t.Fatal(err)
	}
	name, end := s.cur.name, s.cur.end
	_ = s.Close()
	path := filepath.Join(testDir, name)
	f, err := fs.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("garbage that is not a record"), end); err != nil {
		t.Fatal(err)
	}
	_ = f.Sync()
	_ = f.Close()
	withTail, _ := fs.Raw(path)

	s = openFS(t, fs, 0)
	defer s.Close()
	if len(held(t, s)) != 10 || len(s.Notes()) != 1 {
		t.Fatalf("entries before the tail stay, the tail is reported: %v", s.Notes())
	}
	if _, err := s.Append(entries(10, 11)); err != nil {
		t.Fatal(err)
	}
	if s.cur.name == name {
		t.Fatal("new entries never go behind unreadable bytes")
	}
	if now, _ := fs.Raw(path); !bytes.Equal(now, withTail) {
		t.Fatal("the segment with the tail is not changed")
	}
}

func TestStore_RefusesANewerFormatAndServesNothingUnderAnotherKey(t *testing.T) {
	fs := faultfs.New(5)
	s := openFS(t, fs, 0)
	if _, err := s.Append(entries(0, 5)); err != nil {
		t.Fatal(err)
	}
	name := s.cur.name
	_ = s.Close()

	other, err := Open(testDir, Options{FS: fs, Key: []byte("another-key-0123456789abcdef0123"), SegmentSize: 0})
	if err != nil {
		t.Fatal(err)
	}
	if other.Len() != 0 || len(other.Notes()) != 1 {
		t.Fatalf("a segment under another key is not served and is reported: %d %v", other.Len(), other.Notes())
	}
	_ = other.Close()

	path := filepath.Join(testDir, name)
	raw, _ := fs.Raw(path)
	h := append([]byte(nil), raw[:headerSize]...)
	h[4] = verMajor + 1
	putCRC(h)
	fs.Poke(path, 0, h)
	if _, err := Open(testDir, Options{FS: fs, Key: testKey}); !errors.Is(err, ErrVersion) {
		t.Fatalf("a newer major version is refused, never guessed: %v", err)
	}
}

func putCRC(h []byte) {
	binary.LittleEndian.PutUint32(h[headerSize-4:], crc32.Checksum(h[:headerSize-4], castagnoli))
}

func FuzzStore_OpenNeverPanicsOnGarbage(f *testing.F) {
	fs := faultfs.New(6)
	s, _ := Open(testDir, Options{FS: fs, Key: testKey})
	_, _ = s.Append(entries(0, 3))
	_ = s.Close()
	raw, _ := fs.Raw(filepath.Join(testDir, segName(1)))
	f.Add(raw)
	f.Add([]byte{})
	f.Add(raw[:headerSize+5])
	f.Fuzz(func(t *testing.T, data []byte) {
		fs := faultfs.New(7)
		_ = fs.MkdirAll(testDir, 0o700)
		w, err := fs.OpenFile(filepath.Join(testDir, segName(1)), os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.WriteAt(data, 0)
		_ = w.Sync()
		_ = w.Close()
		_ = fs.SyncDir(testDir)
		s, err := Open(testDir, Options{FS: fs, Key: testKey})
		if err != nil {
			return
		}
		_ = s.Each(func(ID, []byte) error { return nil })
		if _, err := s.Append(entries(0, 2)); err != nil {
			t.Fatalf("append after opening garbage: %v", err)
		}
		_ = s.Close()
	})
}

// BenchmarkStore_MemoryPerEntry measures the heap the index needs at a year of busy use (365k entries).
func BenchmarkStore_MemoryPerEntry(b *testing.B) {
	const n = 365000
	for b.Loop() {
		dir := filepath.Join(b.TempDir(), "audit")
		var m0, m1 runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&m0)
		s, err := Open(dir, Options{Key: testKey})
		if err != nil {
			b.Fatal(err)
		}
		batch := make([]StoredEntry, 0, 1000)
		for i := 0; i < n; i++ {
			var id ID
			_, _ = rand.Read(id[:])
			batch = append(batch, StoredEntry{ID: id, Body: []byte(fmt.Sprintf(`{"id":"%x","ts":"2026-11-27T08:29:00.123456Z","actor":"operator-name","node_id":"core-1","action":"config.scopes.save","summary":"scope office: dhcp range changed, 3 reservations changed %d"}`, id, i))})
			if len(batch) == cap(batch) {
				if _, err := s.Append(batch); err != nil {
					b.Fatal(err)
				}
				batch = batch[:0]
			}
		}
		runtime.GC()
		runtime.ReadMemStats(&m1)
		b.ReportMetric(float64(m1.HeapAlloc-m0.HeapAlloc)/n, "heapB/entry")
		_ = s.Close()
	}
}
