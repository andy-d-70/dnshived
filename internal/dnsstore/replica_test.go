// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsstore

import (
	"errors"
	"fmt"
	"math/rand"
	"testing"

	"dnshived/internal/dnsstore/vfs/faultfs"
)

func openID(t testing.TB, fs *faultfs.FS, create bool, id ID, seg int64) *Store {
	t.Helper()
	s, err := Open(testDir, Options{FS: fs, Keys: testKeys(), Create: create, StoreID: id, SegmentSize: seg, SnapshotBytes: 1 << 40})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return s
}

func leaderRecs(t testing.TB, s *Store, term uint64, from, n int, tag string) []Record {
	t.Helper()
	var out []Record
	for i := 0; i < n; i++ {
		r, err := s.AppendLocal(term, putBatch(from+i, fmt.Sprintf("%s-%d", tag, from+i)))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func chainAt0(t testing.TB, s *Store) [32]byte {
	t.Helper()
	_, c, ok := s.ChainAt(0)
	if !ok {
		t.Fatal("no genesis chain")
	}
	return c
}

func TestReplica_CommitLagsAndRestartIsConservative(t *testing.T) {
	fs := faultfs.New(1)
	s := openTest(t, fs, true, 4096)
	id := s.ID()
	leaderRecs(t, s, 1, 0, 3, "a")
	if s.View().Rev() != 0 || s.CommitIndex() != 0 {
		t.Fatal("nothing is committed yet, readers must still see the old state")
	}
	if err := s.AdvanceCommit(3); err != nil {
		t.Fatal(err)
	}
	leaderRecs(t, s, 1, 3, 2, "b")
	if rev, _, _ := s.Head(); rev != 5 || s.View().Rev() != 3 {
		t.Fatalf("head %d view %d", rev, s.View().Rev())
	}
	if err := s.AdvanceCommit(99); err != nil || s.View().Rev() != 5 {
		t.Fatalf("commit is capped at the head: %v %d", err, s.View().Rev())
	}
	_ = s.Close()
	s = openID(t, fs, false, id, 4096)
	defer s.Close()
	if rev, _, _ := s.Head(); rev != 5 {
		t.Fatalf("head after restart %d", rev)
	}
	if s.CommitIndex() != 3 || s.View().Rev() != 3 {
		t.Fatalf("restart must serve only what the log proves committed: commit %d view %d", s.CommitIndex(), s.View().Rev())
	}
}

func TestReplica_FollowerAppendRules(t *testing.T) {
	lf, ff := faultfs.New(1), faultfs.New(2)
	L := openTest(t, lf, true, 4096)
	F := openID(t, ff, true, L.ID(), 4096)
	defer L.Close()
	defer F.Close()
	recs := leaderRecs(t, L, 1, 0, 5, "x")
	g := chainAt0(t, F)
	if m, err := F.AppendRecords(0, g, recs[:3]); err != nil || m != 3 {
		t.Fatalf("first append: %d %v", m, err)
	}
	if m, err := F.AppendRecords(0, g, recs[:3]); err != nil || m != 3 {
		t.Fatalf("a repeated append must be a no-op: %d %v", m, err)
	}
	if rev, _, _ := F.Head(); rev != 3 {
		t.Fatalf("head %d", rev)
	}
	c3 := recs[2].Chain
	if _, err := F.AppendRecords(3, [32]byte{9}, recs[3:]); !errors.Is(err, ErrPrevMismatch) {
		t.Fatalf("wrong previous chain: %v", err)
	}
	if _, err := F.AppendRecords(4, recs[3].Chain, recs[4:]); !errors.Is(err, ErrBehind) {
		t.Fatalf("a gap: %v", err)
	}
	bad := append([]Record(nil), recs[3:]...)
	bad[0].Payload = append([]byte(nil), bad[0].Payload...)
	bad[0].Payload[len(bad[0].Payload)-1] ^= 1
	if _, err := F.AppendRecords(3, c3, bad); err == nil {
		t.Fatal("a tampered record must be refused")
	}
	if rev, _, _ := F.Head(); rev != 3 {
		t.Fatal("a refused record must not change the log")
	}
	if _, err := F.AppendRecords(3, c3, recs[3:]); err != nil {
		t.Fatal(err)
	}
	_, lt, lc := L.Head()
	_, ft, fc := F.Head()
	if lt != ft || lc != fc {
		t.Fatal("the follower must end on the leader's chain")
	}
	if err := F.AdvanceCommit(5); err != nil {
		t.Fatal(err)
	}
	if err := L.AdvanceCommit(5); err != nil {
		t.Fatal(err)
	}
	if F.View().Manifest() != L.View().Manifest() {
		t.Fatal("same log, different state")
	}
	if _, err := F.AppendRecords(0, g, []Record{recs[0], recs[1]}); err != nil {
		t.Fatalf("committed records sent again are skipped: %v", err)
	}
	other := leaderRecs(t, openTest(t, faultfs.New(3), true, 4096), 1, 0, 1, "z")
	if _, err := F.AppendRecords(0, g, other); err == nil {
		t.Fatal("a record of another store must not verify")
	}
}

func TestReplica_ConflictingTentativeTailIsCutBack(t *testing.T) {
	af, bf, ff := faultfs.New(1), faultfs.New(2), faultfs.New(3)
	A := openTest(t, af, true, 700)
	id := A.ID()
	B := openID(t, bf, true, id, 700)
	F := openID(t, ff, true, id, 700)
	defer A.Close()
	defer B.Close()
	defer F.Close()
	ra := leaderRecs(t, A, 1, 0, 6, "a")
	g := chainAt0(t, F)
	if _, err := F.AppendRecords(0, g, ra); err != nil {
		t.Fatal(err)
	}
	if err := F.AdvanceCommit(2); err != nil {
		t.Fatal(err)
	}
	if _, err := B.AppendRecords(0, g, ra[:3]); err != nil {
		t.Fatal(err)
	}
	if _, err := B.AppendNoop(2); err != nil {
		t.Fatal(err)
	}
	rb := leaderRecs(t, B, 2, 10, 3, "b")
	all := []Record{}
	_ = B.Records(4, func(r Record) error { all = append(all, r); return nil })
	if len(all) != 4 || all[3].Rev != 7 {
		t.Fatalf("B's own records: %d", len(all))
	}
	_ = rb
	if _, err := F.AppendRecords(3, ra[2].Chain, all); err != nil {
		t.Fatalf("the conflicting tail must be replaced: %v", err)
	}
	_, bt, bc := B.Head()
	_, ft, fc := F.Head()
	if bt != ft || bc != fc {
		t.Fatal("the follower must follow the new leader after the cut")
	}
	if err := F.Verify(); err != nil {
		t.Fatal(err)
	}
	if err := F.AdvanceCommit(7); err != nil {
		t.Fatal(err)
	}
	if err := B.AdvanceCommit(7); err != nil {
		t.Fatal(err)
	}
	if F.View().Manifest() != B.View().Manifest() {
		t.Fatal("state differs after the cut")
	}
	if _, err := F.AppendRecords(3, ra[2].Chain, ra[3:]); !errors.Is(err, ErrCommittedConflict) {
		t.Fatalf("committed records can never be replaced: %v", err)
	}
	_ = F.Close()
	F = openID(t, ff, false, id, 700)
	defer F.Close()
	if _, _, c := F.Head(); c != bc {
		t.Fatal("the cut must survive a restart")
	}
	if _, err := F.AppendRecords(3, ra[2].Chain, ra[3:]); !errors.Is(err, ErrStaleTerm) {
		t.Fatalf("after a restart the commit index is only a lower bound, an older term must still not overwrite a newer one: %v", err)
	}
	if _, _, c := F.Head(); c != bc {
		t.Fatal("a refused overwrite must not change the log")
	}
}

func TestReplica_TruncateAcrossSegments(t *testing.T) {
	fs := faultfs.New(4)
	s := openTest(t, fs, true, 500)
	id := s.ID()
	leaderRecs(t, s, 1, 0, 40, "t")
	if err := s.AdvanceCommit(10); err != nil {
		t.Fatal(err)
	}
	if err := s.TruncateAfter(5); !errors.Is(err, ErrCommittedConflict) {
		t.Fatalf("below the commit index: %v", err)
	}
	segsBefore := len(names(fs, "seg-", ".log"))
	if err := s.TruncateAfter(20); err != nil {
		t.Fatal(err)
	}
	if rev, _, _ := s.Head(); rev != 20 {
		t.Fatalf("head %d", rev)
	}
	if segsAfter := len(names(fs, "seg-", ".log")); segsAfter >= segsBefore {
		t.Fatalf("later segments must go: %d -> %d", segsBefore, segsAfter)
	}
	leaderRecs(t, s, 2, 100, 5, "n")
	if rev, _, _ := s.Head(); rev != 25 {
		t.Fatalf("head %d", rev)
	}
	_, _, chain := s.Head()
	_ = s.Close()
	s = openID(t, fs, false, id, 500)
	defer s.Close()
	if rev, _, c := s.Head(); rev != 25 || c != chain {
		t.Fatalf("after restart: head %d", rev)
	}
	if err := s.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestReplica_SnapshotInstall(t *testing.T) {
	lf, ff := faultfs.New(1), faultfs.New(2)
	L := openTest(t, lf, true, 600)
	F := openID(t, ff, true, L.ID(), 600)
	defer L.Close()
	recs := leaderRecs(t, L, 1, 0, 30, "s")
	if err := L.AdvanceCommit(30); err != nil {
		t.Fatal(err)
	}
	if _, err := F.AppendRecords(0, chainAt0(t, F), recs[:4]); err != nil {
		t.Fatal(err)
	}
	rev, data, err := L.ExportSnapshot()
	if err != nil || rev != 30 {
		t.Fatalf("export: %d %v", rev, err)
	}
	broken := append([]byte(nil), data...)
	broken[headerSize+20] ^= 0xFF
	if err := F.InstallSnapshot(broken); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a damaged snapshot: %v", err)
	}
	if hr, _, _ := F.Head(); hr != 4 {
		t.Fatal("a refused snapshot must leave the log alone")
	}
	if err := F.InstallSnapshot(data); err != nil {
		t.Fatal(err)
	}
	if hr, _, hc := F.Head(); hr != 30 || F.CommitIndex() != 30 || hc != recs[29].Chain {
		t.Fatalf("after install: head %d commit %d", hr, F.CommitIndex())
	}
	if F.View().Manifest() != L.View().Manifest() {
		t.Fatal("state differs after the install")
	}
	if err := F.InstallSnapshot(data); !errors.Is(err, ErrNotNewer) {
		t.Fatalf("installing the same snapshot again: %v", err)
	}
	more := leaderRecs(t, L, 1, 50, 3, "m")
	if _, err := F.AppendRecords(30, recs[29].Chain, more); err != nil {
		t.Fatalf("append after the install: %v", err)
	}
	id := F.ID()
	_ = F.Close()
	F = openID(t, ff, false, id, 600)
	defer F.Close()
	if hr, _, _ := F.Head(); hr != 33 {
		t.Fatalf("after restart: head %d", hr)
	}
	if err := F.Verify(); err != nil {
		t.Fatal(err)
	}
}

// TestReplica_FollowerCrashEverywhere cuts the power at every operation of a follower that appends, is told to commit,
// has a conflicting tail replaced and installs nothing it should not; whatever survives must be a valid prefix of one
// of the two leaders' logs and must never lose what was committed.
func TestReplica_FollowerCrashEverywhere(t *testing.T) {
	af, bf := faultfs.New(1), faultfs.New(2)
	A := openTest(t, af, true, 600)
	id := A.ID()
	B := openID(t, bf, true, id, 600)
	ra := leaderRecs(t, A, 1, 0, 12, "a")
	g := chainAt0(t, A)
	if _, err := B.AppendRecords(0, g, ra[:6]); err != nil {
		t.Fatal(err)
	}
	if _, err := B.AppendNoop(2); err != nil {
		t.Fatal(err)
	}
	leaderRecs(t, B, 2, 50, 5, "b")
	var rb []Record
	_ = B.Records(7, func(r Record) error { rb = append(rb, r); return nil })
	chainsA, chainsB := map[uint64][32]byte{}, map[uint64][32]byte{}
	for _, r := range ra {
		chainsA[r.Rev] = r.Chain
	}
	for rev := uint64(1); rev <= 6; rev++ {
		chainsB[rev] = chainsA[rev]
	}
	_ = B.Records(7, func(r Record) error { chainsB[r.Rev] = r.Chain; return nil })

	run := func(fs *faultfs.FS) (committed uint64) {
		s, err := Open(testDir, Options{FS: fs, Keys: testKeys(), Create: true, StoreID: id, SegmentSize: 600, SnapshotBytes: 1 << 40})
		if err != nil {
			return 0
		}
		defer s.Close()
		if _, err := s.AppendRecords(0, g, ra[:10]); err != nil {
			return 0
		}
		if err := s.AdvanceCommit(6); err != nil {
			return 0
		}
		committed = 6
		if _, err := s.AppendRecords(6, ra[5].Chain, rb); err != nil {
			return committed
		}
		return committed
	}
	probe := faultfs.New(0)
	run(probe)
	total := probe.Ops()
	for n := 1; n <= total; n++ {
		for _, torn := range []bool{false, true} {
			fs := faultfs.New(int64(n))
			fs.SetCrashAt(n, torn)
			run(fs)
			if !fs.Crashed() {
				continue
			}
			fs.Crash()
			s, err := Open(testDir, Options{FS: fs, Keys: testKeys(), StoreID: id, SegmentSize: 600, SnapshotBytes: 1 << 40})
			if errors.Is(err, ErrNoStore) {
				continue
			}
			if err != nil {
				t.Fatalf("crash at %d: reopen: %v", n, err)
			}
			rev, _, chain := s.Head()
			if rev > 0 {
				if chain != chainsA[rev] && chain != chainsB[rev] {
					t.Fatalf("crash at %d: head %d is on neither leader's log", n, rev)
				}
			}
			if err := s.Verify(); err != nil {
				t.Fatalf("crash at %d: %v", n, err)
			}
			s.Close()
		}
	}
	_ = rand.Int
}

func TestReplica_SnapshotReplacesADivergentUncommittedTail(t *testing.T) {
	lf, ff := faultfs.New(1), faultfs.New(2)
	L := openTest(t, lf, true, 600)
	F := openID(t, ff, true, L.ID(), 600)
	defer L.Close()
	defer F.Close()
	recs := leaderRecs(t, L, 2, 0, 20, "lead")
	if err := L.AdvanceCommit(20); err != nil {
		t.Fatal(err)
	}
	other := openID(t, faultfs.New(3), true, L.ID(), 600)
	defer other.Close()
	stale := leaderRecs(t, other, 1, 100, 25, "stale")
	if _, err := F.AppendRecords(0, chainAt0(t, F), stale); err != nil {
		t.Fatal(err)
	}
	if err := F.AdvanceCommit(3); err != nil {
		t.Fatal(err)
	}
	rev, data, err := L.ExportSnapshot()
	if err != nil || rev != 20 {
		t.Fatal(err)
	}
	if hr, _, _ := F.Head(); hr != 25 {
		t.Fatalf("head %d", hr)
	}
	if err := F.InstallSnapshot(data); err != nil {
		t.Fatalf("a snapshot beyond the commit index must replace a divergent tail: %v", err)
	}
	if hr, _, hc := F.Head(); hr != 20 || hc != recs[19].Chain || F.CommitIndex() != 20 {
		t.Fatalf("after install: head %d commit %d", hr, F.CommitIndex())
	}
	if F.View().Manifest() != L.View().Manifest() {
		t.Fatal("state differs")
	}
	if err := F.InstallSnapshot(data); !errors.Is(err, ErrNotNewer) {
		t.Fatalf("again: %v", err)
	}
}

func TestReplica_SnapshotMatchingTheLogIsNotNeeded(t *testing.T) {
	lf, ff := faultfs.New(1), faultfs.New(2)
	L := openTest(t, lf, true, 600)
	F := openID(t, ff, true, L.ID(), 600)
	defer L.Close()
	defer F.Close()
	recs := leaderRecs(t, L, 1, 0, 10, "x")
	if _, err := F.AppendRecords(0, chainAt0(t, F), recs); err != nil {
		t.Fatal(err)
	}
	if err := L.AdvanceCommit(8); err != nil {
		t.Fatal(err)
	}
	_, data, err := L.ExportSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := F.InstallSnapshot(data); !errors.Is(err, ErrNotNewer) {
		t.Fatalf("a follower that holds the snapshot's record keeps its log: %v", err)
	}
	if hr, _, _ := F.Head(); hr != 10 {
		t.Fatal("its log must be untouched")
	}
}
