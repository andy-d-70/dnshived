// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsstore

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	ringCap      = 512
	MaxTentative = ringCap / 2
)

// ringEnt remembers a recent record: its place in the log and the view after it, so a tentative tail can be cut back.
type ringEnt struct {
	rev   uint64
	term  uint64
	chain [chainSize]byte
	view  *View
	seg   string
	off   int64
}

func (s *Store) pushRing(e ringEnt) {
	s.ring = append(s.ring, e)
	if n := len(s.ring); n > ringCap {
		copy(s.ring, s.ring[n-ringCap:])
		s.ring = s.ring[:ringCap]
	}
}

func (s *Store) ringIndex(rev uint64) int {
	if len(s.ring) == 0 || rev < s.ring[0].rev {
		return -1
	}
	i := int(rev - s.ring[0].rev)
	if i >= len(s.ring) {
		return -1
	}
	return i
}

func (s *Store) viewAtLocked(rev uint64) (*View, bool) {
	if s.base != nil && rev == s.base.rev {
		return s.base, true
	}
	if i := s.ringIndex(rev); i >= 0 {
		return s.ring[i].view, true
	}
	return nil, false
}

// ChainAt returns the term and chain value of the record at rev, when it is still remembered.
func (s *Store) ChainAt(rev uint64) (term uint64, chain [32]byte, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.chainAtLocked(rev)
}

func (s *Store) chainAtLocked(rev uint64) (uint64, [32]byte, bool) {
	if rev == s.head.rev {
		return s.head.term, s.head.chain, true
	}
	if rev == s.base.rev {
		return s.base.term, s.base.chain, true
	}
	if i := s.ringIndex(rev); i >= 0 {
		return s.ring[i].term, s.ring[i].chain, true
	}
	return 0, [32]byte{}, false
}

// HeadView is the state including records that are not committed yet; readers should use View.
func (s *Store) HeadView() *View {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.head
}

// AdvanceCommit marks everything up to rev committed (never beyond the head) and publishes that state to readers.
func (s *Store) AdvanceCommit(rev uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	rev = min(rev, s.head.rev)
	if rev <= s.commit {
		return nil
	}
	v, ok := s.viewAtLocked(rev)
	if !ok {
		return fmt.Errorf("%w: revision %d is out of the recent window", ErrCannotTruncate, rev)
	}
	s.commit = rev
	s.cur.Store(v)
	s.maybeSnapshotLocked()
	return nil
}

func (s *Store) appendRepl(typ byte, term uint64, payload []byte, ops []Op, epoch uint32) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.head != nil && s.head.rev-s.commit >= MaxTentative {
		return Record{}, ErrBackpressure
	}
	prevEpoch := s.head.keyEpoch
	commit := s.commit
	nv, err := s.appendLocked(typ, term, payload, ops, epoch, false)
	if err != nil {
		return Record{}, err
	}
	e := s.ring[len(s.ring)-1]
	return Record{Type: typ, KeyEpoch: prevEpoch, Term: e.term, Rev: nv.rev, Commit: commit, Payload: payload, Chain: e.chain}, nil
}

// AppendLocal appends a batch as a leader of term: durable, but committed only once AdvanceCommit says so.
func (s *Store) AppendLocal(term uint64, b Batch) (Record, error) {
	payload, err := encodeBatch(&b)
	if err != nil {
		return Record{}, err
	}
	return s.appendRepl(recBatch, term, payload, b.Ops, 0)
}

// AppendNoop appends the empty record a new leader writes to start its term.
func (s *Store) AppendNoop(term uint64) (Record, error) {
	return s.appendRepl(recNoop, term, nil, nil, 0)
}

// AppendRotateLocal appends a key rotation as a leader.
func (s *Store) AppendRotateLocal(term uint64, epoch uint32) (Record, error) {
	var p [4]byte
	le.PutUint32(p[:], epoch)
	s.mu.Lock()
	_, ok := s.keys.Key(epoch)
	cur := s.head.keyEpoch
	s.mu.Unlock()
	if !ok || epoch <= cur {
		return Record{}, fmt.Errorf("%w: rotation to epoch %d", ErrKey, epoch)
	}
	return s.appendRepl(recRotate, term, p[:], nil, epoch)
}

// truncateAfterLocked cuts the log back to rev. Only records above the commit index can be cut.
func (s *Store) truncateAfterLocked(rev uint64) error {
	if rev >= s.head.rev {
		return nil
	}
	if rev < s.commit {
		return ErrCommittedConflict
	}
	idx := s.ringIndex(rev)
	if idx < 0 || s.ring[idx].seg == "" {
		return ErrCannotTruncate
	}
	e := s.ring[idx]
	if s.seg != nil {
		_ = s.seg.f.Close()
		s.seg = nil
	}
	for len(s.segs) > 0 && s.segs[len(s.segs)-1].firstRev > rev {
		last := s.segs[len(s.segs)-1]
		if err := s.fs.Remove(filepath.Join(s.dir, last.name)); err != nil {
			return s.fail(err)
		}
		s.segs = s.segs[:len(s.segs)-1]
	}
	if err := s.fs.SyncDir(s.dir); err != nil {
		return s.fail(err)
	}
	f, err := s.fs.OpenFile(filepath.Join(s.dir, e.seg), os.O_RDWR, 0)
	if err != nil {
		return s.fail(err)
	}
	size, err := f.Size()
	if err == nil {
		err = zeroTail(f, e.off, size)
	}
	if err != nil {
		_ = f.Close()
		return s.fail(err)
	}
	var info segInfo
	for _, si := range s.segs {
		if si.name == e.seg {
			info = si
		}
	}
	s.seg = &segment{f: f, info: info, off: e.off, size: size}
	s.head = e.view
	s.ring = s.ring[:idx+1]
	if nk, ok := s.keys.Key(e.view.keyEpoch); ok {
		s.hasher = newRowHasher(nk)
	}
	return nil
}

// TruncateAfter cuts back an uncommitted tail; it refuses to touch anything committed.
func (s *Store) TruncateAfter(rev uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	return s.truncateAfterLocked(rev)
}

func recordOf(r Record) record {
	return record{typ: r.Type, keyEpoch: r.KeyEpoch, term: r.Term, rev: r.Rev, commit: r.Commit, payload: r.Payload, chain: r.Chain}
}

func (s *Store) appendOneLocked(r Record) error {
	v := s.head
	if r.Term < v.term {
		return ErrStaleTerm
	}
	if r.Commit > r.Rev {
		return fmt.Errorf("%w: commit index above revision", ErrBadChain)
	}
	if r.KeyEpoch != v.keyEpoch {
		return fmt.Errorf("%w: epoch %d, expected %d", ErrKey, r.KeyEpoch, v.keyEpoch)
	}
	key, ok := s.keys.Key(v.keyEpoch)
	if !ok {
		return fmt.Errorf("%w: %d", ErrKey, v.keyEpoch)
	}
	rec := recordOf(r)
	if chainNext(key, v.chain, rec.typ, rec.keyEpoch, rec.term, rec.rev, rec.commit, rec.payload) != rec.chain {
		return ErrBadChain
	}
	var ops []Op
	var epoch uint32
	switch r.Type {
	case recBatch:
		b, err := decodeBatch(r.Payload)
		if err != nil {
			return err
		}
		ops = b.Ops
	case recNoop:
	case recRotate:
		if len(r.Payload) != 4 {
			return fmt.Errorf("%w: rotate record", ErrBadChain)
		}
		epoch = le.Uint32(r.Payload)
		if _, ok := s.keys.Key(epoch); !ok || epoch <= v.keyEpoch {
			return fmt.Errorf("%w: rotation to epoch %d", ErrKey, epoch)
		}
	default:
		return fmt.Errorf("%w: record type %d", ErrVersion, r.Type)
	}
	_, err := s.writeRecordLocked(&rec, ops, epoch)
	return err
}

// AppendRecords adds records received from a leader after the record (prevRev, prevChain). Records it already holds are
// skipped; an uncommitted record that differs is cut away with everything after it. It returns the revision the log
// matches the leader up to. ErrBehind and ErrPrevMismatch tell the leader to back up.
func (s *Store) AppendRecords(prevRev uint64, prevChain [32]byte, recs []Record) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, ErrClosed
	}
	if s.failed != nil {
		return 0, fmt.Errorf("%w: %v", ErrFailed, s.failed)
	}
	if prevRev > s.head.rev {
		return 0, ErrBehind
	}
	if prevRev > s.commit {
		_, c, ok := s.chainAtLocked(prevRev)
		if !ok || c != prevChain {
			return 0, ErrPrevMismatch
		}
	} else if t, c, ok := s.chainAtLocked(prevRev); ok && c != prevChain {
		_ = t
		return 0, ErrCommittedConflict
	}
	for i, r := range recs {
		if r.Rev != prevRev+1+uint64(i) {
			return 0, fmt.Errorf("%w: revision %d at position %d after %d", ErrBadChain, r.Rev, i, prevRev)
		}
		if r.Rev <= s.head.rev {
			_, c, ok := s.chainAtLocked(r.Rev)
			switch {
			case ok && c == r.Chain:
				continue
			case !ok && r.Rev <= s.commit:
				continue
			case r.Rev <= s.commit:
				return 0, ErrCommittedConflict
			}
			if have, _, ok := s.chainAtLocked(r.Rev); ok && have > r.Term {
				return 0, ErrStaleTerm
			}
			if err := s.truncateAfterLocked(r.Rev - 1); err != nil {
				return 0, err
			}
		}
		if err := s.appendOneLocked(r); err != nil {
			return 0, err
		}
	}
	return prevRev + uint64(len(recs)), nil
}

// ExportSnapshot returns a snapshot of the committed state for a follower that is too far behind.
func (s *Store) ExportSnapshot() (rev uint64, data []byte, err error) {
	if err := s.Snapshot(); err != nil {
		return 0, nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.snaps) == 0 {
		return 0, nil, fmt.Errorf("%w: nothing is committed yet", ErrGap)
	}
	sn := s.snaps[len(s.snaps)-1]
	f, err := s.fs.OpenFile(filepath.Join(s.dir, sn.name), os.O_RDONLY, 0)
	if err != nil {
		return 0, nil, err
	}
	defer f.Close()
	size, err := f.Size()
	if err != nil {
		return 0, nil, err
	}
	data = make([]byte, size)
	if _, err := f.ReadAt(data, 0); err != nil {
		return 0, nil, err
	}
	return sn.rev, data, nil
}

// InstallSnapshot replaces the whole log with a snapshot from the leader. It is allowed only when the snapshot is
// beyond this log's commit index and this log does not hold the snapshot's record, so nothing committed is lost; what
// is dropped is uncommitted tail that disagrees with the leader.
func (s *Store) InstallSnapshot(data []byte) error {
	s.snapWG.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if s.failed != nil {
		return fmt.Errorf("%w: %v", ErrFailed, s.failed)
	}
	tmp := filepath.Join(s.dir, "snap-install.tmp")
	_ = s.fs.Remove(tmp)
	f, err := s.fs.OpenFile(tmp, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	_, err = f.WriteAt(data, 0)
	if err == nil {
		err = f.Sync()
	}
	_ = f.Close()
	if err != nil {
		_ = s.fs.Remove(tmp)
		return err
	}
	v, err := loadSnapshot(s.fs, tmp, s.id, s.keys)
	if err != nil {
		_ = s.fs.Remove(tmp)
		return err
	}
	if v.rev <= s.commit {
		_ = s.fs.Remove(tmp)
		return fmt.Errorf("%w: snapshot at %d, committed up to %d", ErrNotNewer, v.rev, s.commit)
	}
	if v.rev <= s.head.rev {
		if _, c, ok := s.chainAtLocked(v.rev); ok && c == v.chain {
			_ = s.fs.Remove(tmp)
			return fmt.Errorf("%w: the log already holds the snapshot's record %d", ErrNotNewer, v.rev)
		}
	}
	if err := s.fs.Rename(tmp, filepath.Join(s.dir, snapName(v.rev))); err != nil {
		return s.fail(err)
	}
	if err := s.fs.SyncDir(s.dir); err != nil {
		return s.fail(err)
	}
	if s.seg != nil {
		_ = s.seg.f.Close()
		s.seg = nil
	}
	for _, si := range s.segs {
		if err := s.fs.Remove(filepath.Join(s.dir, si.name)); err != nil {
			return s.fail(err)
		}
	}
	s.segs = nil
	for _, sn := range s.snaps {
		if sn.rev < v.rev {
			_ = s.fs.Remove(filepath.Join(s.dir, sn.name))
		}
	}
	s.snaps = []snapInfo{{v.rev, snapName(v.rev)}}
	if err := s.fs.SyncDir(s.dir); err != nil {
		return s.fail(err)
	}
	key, ok := s.keys.Key(v.keyEpoch)
	if !ok {
		return s.fail(fmt.Errorf("%w: %d", ErrKey, v.keyEpoch))
	}
	s.hasher = newRowHasher(key)
	s.head, s.base, s.ring = v, v, nil
	s.commit = v.rev
	s.cur.Store(v)
	s.logBytes, s.snapMark = 0, 0
	return nil
}
