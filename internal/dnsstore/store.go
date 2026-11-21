// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsstore

import (
	"bufio"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"dnshived/internal/dnsstore/vfs"
)

const (
	defaultSegment  = 64 << 20
	defaultSnapshot = 64 << 20
	keepSnapshots   = 2
)

type Options struct {
	FS            vfs.FS
	Keys          Keys
	Create        bool
	StoreID       ID
	SegmentSize   int64
	SnapshotBytes int64
}

type segInfo struct {
	firstRev uint64
	name     string
}

type snapInfo struct {
	rev  uint64
	name string
}

type segment struct {
	f    vfs.File
	info segInfo
	off  int64
	size int64
}

type Store struct {
	fs        vfs.FS
	dir       string
	keys      Keys
	segSize   int64
	snapBytes int64
	id        ID
	dirLock   io.Closer

	cur atomic.Pointer[View]

	mu        sync.Mutex
	head      *View
	commit    uint64
	ring      []ringEnt
	base      *View
	maxCommit uint64
	hasher    *rowHasher
	seg       *segment
	segs      []segInfo
	snaps     []snapInfo
	logBytes  int64
	snapMark  int64
	snapBusy  bool
	snapWG    sync.WaitGroup
	snapErr   error
	failed    error
	closed    bool
	recovered RecoveryInfo
}

// RecoveryInfo reports what Open had to repair.
type RecoveryInfo struct {
	TruncatedBytes   int64
	DroppedSegment   string
	SkippedSnapshots []string
}

func segName(rev uint64) string { return fmt.Sprintf("seg-%016x.log", rev) }

func parseName(name, prefix, suffix string) (uint64, bool) {
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) || len(name) != len(prefix)+16+len(suffix) {
		return 0, false
	}
	n, err := strconv.ParseUint(name[len(prefix):len(prefix)+16], 16, 64)
	return n, err == nil
}

func Open(dir string, o Options) (*Store, error) {
	if o.FS == nil {
		o.FS = vfs.OS{}
	}
	if o.Keys == nil {
		return nil, fmt.Errorf("%w: no keys", ErrKey)
	}
	if o.SegmentSize <= 0 {
		o.SegmentSize = defaultSegment
	}
	if o.SnapshotBytes <= 0 {
		o.SnapshotBytes = defaultSnapshot
	}
	if err := o.FS.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	mode, err := o.FS.Mode(dir)
	if err != nil {
		return nil, err
	}
	if !mode.IsDir() || mode.Perm()&0o022 != 0 {
		return nil, fmt.Errorf("%w: %s is %v, it must be a directory writable only by its owner", ErrPermissions, dir, mode)
	}
	lock, err := o.FS.Lock(filepath.Join(dir, "LOCK"))
	if err != nil {
		return nil, err
	}
	s := &Store{fs: o.FS, dir: dir, keys: o.Keys, segSize: o.SegmentSize, snapBytes: o.SnapshotBytes, dirLock: lock}
	if err := s.open(o); err != nil {
		if s.seg != nil {
			_ = s.seg.f.Close()
		}
		_ = lock.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) open(o Options) error {
	id, err := s.openMeta(o)
	if err != nil {
		return err
	}
	s.id = id
	_ = s.fs.Remove(filepath.Join(s.dir, "snap.tmp"))
	names, err := s.fs.ReadDir(s.dir)
	if err != nil {
		return err
	}
	for _, n := range names {
		if rev, ok := parseName(n, "seg-", ".log"); ok {
			s.segs = append(s.segs, segInfo{rev, n})
		} else if rev, ok := parseName(n, "snap-", ".snap"); ok {
			s.snaps = append(s.snaps, snapInfo{rev, n})
		}
	}
	sort.Slice(s.segs, func(i, j int) bool { return s.segs[i].firstRev < s.segs[j].firstRev })
	sort.Slice(s.snaps, func(i, j int) bool { return s.snaps[i].rev < s.snaps[j].rev })
	base, err := s.loadBase()
	if err != nil {
		return err
	}
	v, err := s.replay(base)
	if err != nil {
		return err
	}
	if v == nil {
		epoch := s.keys.Current()
		key, ok := s.keys.Key(epoch)
		if !ok {
			return fmt.Errorf("%w: %d", ErrKey, epoch)
		}
		v = genesisView(genesisChain(key, s.id), epoch)
	}
	key, ok := s.keys.Key(v.keyEpoch)
	if !ok {
		return fmt.Errorf("%w: %d", ErrKey, v.keyEpoch)
	}
	s.hasher = newRowHasher(key)
	s.head = v
	if s.base == nil {
		s.base = v
	}
	s.commit = min(max(s.maxCommit, s.base.rev), v.rev)
	cv, ok := s.viewAtLocked(s.commit)
	if !ok {
		cv, s.commit = s.base, s.base.rev
	}
	s.cur.Store(cv)
	return nil
}

func (s *Store) openMeta(o Options) (ID, error) {
	path := filepath.Join(s.dir, "store.meta")
	f, err := s.fs.OpenFile(path, os.O_RDONLY, 0)
	if err == nil {
		defer f.Close()
		b := make([]byte, headerSize)
		if _, err := f.ReadAt(b, 0); err != nil {
			return ID{}, corrupt(path, 0, "%v", err)
		}
		h, err := decodeHeader(b, path)
		if err != nil {
			return ID{}, err
		}
		if h.ftype != ftMeta {
			return ID{}, corrupt(path, 4, "not a store meta file")
		}
		if o.StoreID != (ID{}) && o.StoreID != h.storeID {
			return ID{}, ErrStoreID
		}
		return h.storeID, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return ID{}, err
	}
	if !o.Create {
		return ID{}, ErrNoStore
	}
	id := o.StoreID
	if id == (ID{}) {
		if _, err := rand.Read(id[:]); err != nil {
			return ID{}, err
		}
	}
	tmp := path + ".tmp"
	_ = s.fs.Remove(tmp)
	tf, err := s.fs.OpenFile(tmp, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return ID{}, err
	}
	if _, err := tf.WriteAt(encodeHeader(header{ftype: ftMeta, major: verMajor, minor: verMinor, storeID: id}), 0); err != nil {
		_ = tf.Close()
		return ID{}, err
	}
	if err := tf.Sync(); err != nil {
		_ = tf.Close()
		return ID{}, err
	}
	if err := tf.Close(); err != nil {
		return ID{}, err
	}
	if err := s.fs.Rename(tmp, path); err != nil {
		return ID{}, err
	}
	return id, s.fs.SyncDir(s.dir)
}

func (s *Store) loadBase() (*View, error) {
	for i := len(s.snaps) - 1; i >= 0; i-- {
		sn := s.snaps[i]
		v, err := loadSnapshot(s.fs, filepath.Join(s.dir, sn.name), s.id, s.keys)
		if err == nil {
			return v, nil
		}
		if !errors.Is(err, ErrCorrupt) {
			return nil, err
		}
		s.recovered.SkippedSnapshots = append(s.recovered.SkippedSnapshots, sn.name)
		_ = s.fs.Rename(filepath.Join(s.dir, sn.name), filepath.Join(s.dir, sn.name+".corrupt"))
		s.snaps = append(s.snaps[:i], s.snaps[i+1:]...)
	}
	return nil, nil
}

func zeroTail(f vfs.File, from, size int64) error {
	zero := make([]byte, 64<<10)
	for off := from; off < size; {
		n := int64(len(zero))
		if size-off < n {
			n = size - off
		}
		if _, err := f.WriteAt(zero[:n], off); err != nil {
			return err
		}
		off += n
	}
	return f.SyncData()
}

// replay applies the log after base (nil means an empty store) and repairs a torn tail of the last segment.
func (s *Store) replay(base *View) (*View, error) {
	v := base
	s.base = base
	var hasher *rowHasher
	if v != nil {
		key, ok := s.keys.Key(v.keyEpoch)
		if !ok {
			return nil, fmt.Errorf("%w: %d", ErrKey, v.keyEpoch)
		}
		hasher = newRowHasher(key)
	}
	start := uint64(0)
	if v != nil {
		start = v.rev
	}
	for i := 0; i < len(s.segs); i++ {
		si := s.segs[i]
		last := i == len(s.segs)-1
		if !last && s.segs[i+1].firstRev-1 <= start {
			continue
		}
		path := filepath.Join(s.dir, si.name)
		f, err := s.fs.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			return nil, err
		}
		size, err := f.Size()
		if err != nil {
			_ = f.Close()
			return nil, err
		}
		hb := make([]byte, headerSize)
		_, rerr := f.ReadAt(hb, 0)
		h, herr := decodeHeader(hb, path)
		if rerr != nil && size >= headerSize {
			_ = f.Close()
			return nil, rerr
		}
		if size < headerSize || herr != nil {
			_ = f.Close()
			if !last || errors.Is(herr, ErrVersion) {
				if herr == nil {
					herr = corrupt(path, 0, "short header")
				}
				return nil, herr
			}
			if err := s.fs.Remove(path); err != nil {
				return nil, err
			}
			if err := s.fs.SyncDir(s.dir); err != nil {
				return nil, err
			}
			s.recovered.DroppedSegment = si.name
			s.segs = s.segs[:i]
			break
		}
		if h.ftype != ftLog || h.storeID != s.id || h.firstRev != si.firstRev {
			_ = f.Close()
			return nil, corrupt(path, 0, "header does not match the file name or store")
		}
		br := bufio.NewReaderSize(io.NewSectionReader(f, headerSize, size-headerSize), 256<<10)
		off := int64(headerSize)
		first := true
		var segLast uint64
		for {
			rec, n, err := readRecord(br, size-off)
			if err == errEnd {
				break
			}
			if err == errTorn {
				if !last {
					_ = f.Close()
					return nil, corrupt(path, off, "damaged record before the last segment")
				}
				if zerr := zeroTail(f, off, size); zerr != nil {
					_ = f.Close()
					return nil, zerr
				}
				s.recovered.TruncatedBytes += size - off
				break
			}
			if first && rec.rev != si.firstRev {
				_ = f.Close()
				return nil, corrupt(path, off, "first record is revision %d, the file name says %d", rec.rev, si.firstRev)
			}
			first = false
			segLast = rec.rev
			if v == nil {
				key, ok := s.keys.Key(rec.keyEpoch)
				if !ok {
					_ = f.Close()
					return nil, fmt.Errorf("%w: %d in %s", ErrKey, rec.keyEpoch, path)
				}
				v = genesisView(genesisChain(key, s.id), rec.keyEpoch)
				s.base = v
				hasher = newRowHasher(key)
			}
			if rec.commit > rec.rev {
				_ = f.Close()
				return nil, corrupt(path, off, "commit index %d is above revision %d", rec.commit, rec.rev)
			}
			if rec.rev <= v.rev {
				if rec.rev == v.rev && rec.chain != v.chain {
					_ = f.Close()
					return nil, corrupt(path, off, "chain differs from the snapshot at revision %d", rec.rev)
				}
				s.maxCommit = max(s.maxCommit, rec.commit)
				off += n
				continue
			}
			nv, err := s.applyRecord(v, hasher, rec, path, off)
			if err != nil {
				_ = f.Close()
				return nil, err
			}
			if nv.keyEpoch != v.keyEpoch {
				key, _ := s.keys.Key(nv.keyEpoch)
				hasher = newRowHasher(key)
			}
			v = nv
			off += n
			s.maxCommit = max(s.maxCommit, rec.commit)
			s.pushRing(ringEnt{rev: rec.rev, term: rec.term, chain: rec.chain, view: nv, seg: si.name, off: off})
		}
		head := uint64(0)
		if v != nil {
			head = v.rev
			start = v.rev
		}
		reuse := last && (first && si.firstRev == head+1 || !first && segLast == head)
		if reuse {
			s.seg = &segment{f: f, info: si, off: off, size: size}
		} else {
			_ = f.Close()
		}
	}
	return v, nil
}

func (s *Store) applyRecord(v *View, h *rowHasher, rec record, path string, off int64) (*View, error) {
	if rec.rev != v.rev+1 {
		return nil, corrupt(path, off, "revision %d after %d", rec.rev, v.rev)
	}
	if rec.keyEpoch != v.keyEpoch || rec.term < v.term {
		return nil, corrupt(path, off, "key epoch %d or term %d out of order at revision %d", rec.keyEpoch, rec.term, rec.rev)
	}
	key, ok := s.keys.Key(rec.keyEpoch)
	if !ok {
		return nil, fmt.Errorf("%w: %d in %s", ErrKey, rec.keyEpoch, path)
	}
	if chainNext(key, v.chain, rec.typ, rec.keyEpoch, rec.term, rec.rev, rec.commit, rec.payload) != rec.chain {
		return nil, corrupt(path, off, "chain mismatch at revision %d", rec.rev)
	}
	switch rec.typ {
	case recBatch:
		b, err := decodeBatch(rec.payload)
		if err != nil {
			return nil, corrupt(path, off, "revision %d: %v", rec.rev, err)
		}
		return v.withOps(b.Ops, rec.rev, rec.term, rec.chain, h), nil
	case recNoop:
		return v.withOps(nil, rec.rev, rec.term, rec.chain, h), nil
	case recRotate:
		if len(rec.payload) != 4 {
			return nil, corrupt(path, off, "rotate record of %d bytes", len(rec.payload))
		}
		epoch := le.Uint32(rec.payload)
		nkey, ok := s.keys.Key(epoch)
		if !ok || epoch <= v.keyEpoch {
			return nil, fmt.Errorf("%w: rotation to epoch %d in %s", ErrKey, epoch, path)
		}
		return v.withRotation(rec.rev, rec.term, rec.chain, epoch, newRowHasher(nkey)), nil
	default:
		return nil, fmt.Errorf("%w: record type %d in %s", ErrVersion, rec.typ, path)
	}
}

func (s *Store) View() *View { return s.cur.Load() }

func (s *Store) ID() ID { return s.id }

// Head reports the newest record, including records not yet committed.
func (s *Store) Head() (rev, term uint64, chain [32]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.head.rev, s.head.term, s.head.chain
}

// CommitIndex is the highest revision known to be committed; View shows the state at that revision.
func (s *Store) CommitIndex() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.commit
}

func (s *Store) Recovery() RecoveryInfo { return s.recovered }

func (s *Store) fail(err error) error {
	if s.failed == nil {
		s.failed = err
	}
	return fmt.Errorf("%w: %v", ErrFailed, err)
}

// Commit appends one batch at the next revision and returns once it is durable.
func (s *Store) Commit(b Batch) (uint64, error) {
	payload, err := encodeBatch(&b)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, err := s.appendLocked(recBatch, 0, payload, b.Ops, 0, true)
	if err != nil {
		return 0, err
	}
	return v.rev, nil
}

// Rotate switches the chain and partition hashes to a new key epoch whose key the Keys source already holds.
func (s *Store) Rotate(epoch uint32) (uint64, error) {
	var p [4]byte
	le.PutUint32(p[:], epoch)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys.Key(epoch); !ok || epoch <= s.head.keyEpoch {
		return 0, fmt.Errorf("%w: rotation to epoch %d", ErrKey, epoch)
	}
	v, err := s.appendLocked(recRotate, 0, p[:], nil, epoch, true)
	if err != nil {
		return 0, err
	}
	return v.rev, nil
}

// SetTerm writes a no-op record that starts a new term; terms never decrease.
func (s *Store) SetTerm(term uint64) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if term < s.head.term {
		return 0, fmt.Errorf("%w: term %d is below %d", ErrBadBatch, term, s.head.term)
	}
	v, err := s.appendLocked(recNoop, term, nil, nil, 0, true)
	if err != nil {
		return 0, err
	}
	return v.rev, nil
}

func (s *Store) appendLocked(typ byte, term uint64, payload []byte, ops []Op, epoch uint32, selfCommit bool) (*View, error) {
	if s.closed {
		return nil, ErrClosed
	}
	if s.failed != nil {
		return nil, fmt.Errorf("%w: %v", ErrFailed, s.failed)
	}
	v := s.head
	if term == 0 {
		term = max(v.term, 1)
	}
	if term < v.term {
		return nil, fmt.Errorf("%w: term %d is below %d", ErrBadBatch, term, v.term)
	}
	key, ok := s.keys.Key(v.keyEpoch)
	if !ok {
		return nil, fmt.Errorf("%w: %d", ErrKey, v.keyEpoch)
	}
	rec := record{typ: typ, keyEpoch: v.keyEpoch, term: term, rev: v.rev + 1, commit: s.commit, payload: payload}
	if selfCommit {
		rec.commit = rec.rev
	}
	rec.chain = chainNext(key, v.chain, rec.typ, rec.keyEpoch, rec.term, rec.rev, rec.commit, rec.payload)
	nv, err := s.writeRecordLocked(&rec, ops, epoch)
	if err != nil {
		return nil, err
	}
	if selfCommit {
		s.commit = rec.rev
		s.cur.Store(nv)
		s.maybeSnapshotLocked()
	}
	return nv, nil
}

// writeRecordLocked appends a fully built record to the log, makes it durable and applies it to the head view.
func (s *Store) writeRecordLocked(rec *record, ops []Op, epoch uint32) (*View, error) {
	b := encodeRecord(rec)
	if err := s.ensureSegment(rec.rev, int64(len(b))); err != nil {
		return nil, s.fail(err)
	}
	if _, err := s.seg.f.WriteAt(b, s.seg.off); err != nil {
		return nil, s.fail(err)
	}
	if err := s.seg.f.SyncData(); err != nil {
		return nil, s.fail(err)
	}
	s.seg.off += int64(len(b))
	s.logBytes += int64(len(b))
	v := s.head
	var nv *View
	switch rec.typ {
	case recBatch, recNoop:
		nv = v.withOps(ops, rec.rev, rec.term, rec.chain, s.hasher)
	case recRotate:
		nkey, _ := s.keys.Key(epoch)
		s.hasher = newRowHasher(nkey)
		nv = v.withRotation(rec.rev, rec.term, rec.chain, epoch, s.hasher)
	}
	s.head = nv
	s.pushRing(ringEnt{rev: rec.rev, term: rec.term, chain: rec.chain, view: nv, seg: s.seg.info.name, off: s.seg.off})
	return nv, nil
}

func (s *Store) maybeSnapshotLocked() {
	if s.logBytes-s.snapMark >= s.snapBytes && !s.snapBusy {
		s.snapBusy = true
		s.snapWG.Add(1)
		go s.snapshotAsync()
	}
}

func (s *Store) ensureSegment(rev uint64, need int64) error {
	if s.seg != nil && s.seg.off+need <= s.seg.size {
		return nil
	}
	size := s.segSize
	if min := headerSize + need; size < min {
		size = min
	}
	if s.seg != nil {
		_ = s.seg.f.Close()
		s.seg = nil
	}
	info := segInfo{firstRev: rev, name: segName(rev)}
	path := filepath.Join(s.dir, info.name)
	f, err := s.fs.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteAt(encodeHeader(header{ftype: ftLog, major: verMajor, minor: verMinor, storeID: s.id, firstRev: rev}), 0); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Preallocate(size); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := s.fs.SyncDir(s.dir); err != nil {
		_ = f.Close()
		return err
	}
	s.seg = &segment{f: f, info: info, off: headerSize, size: size}
	s.segs = append(s.segs, info)
	return nil
}

func (s *Store) snapshotAsync() {
	defer s.snapWG.Done()
	err := s.snapshot()
	s.mu.Lock()
	s.snapBusy = false
	s.snapErr = err
	s.mu.Unlock()
}

// Snapshot writes a snapshot of the current state and prunes what it makes unnecessary.
func (s *Store) Snapshot() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	if s.failed != nil {
		err := s.failed
		s.mu.Unlock()
		return fmt.Errorf("%w: %v", ErrFailed, err)
	}
	s.mu.Unlock()
	return s.snapshot()
}

// SnapshotError is the result of the last automatic snapshot.
func (s *Store) SnapshotError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapErr
}

func (s *Store) snapshot() error {
	s.mu.Lock()
	v := s.cur.Load()
	mark := s.logBytes
	if n := len(s.snaps); n > 0 && s.snaps[n-1].rev == v.rev || v.rev == 0 {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()
	if err := writeSnapshot(s.fs, s.dir, v, s.id); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if n := len(s.snaps); n > 0 && s.snaps[n-1].rev >= v.rev {
		_ = s.fs.Remove(filepath.Join(s.dir, snapName(v.rev)))
		return nil
	}
	s.snaps = append(s.snaps, snapInfo{v.rev, snapName(v.rev)})
	s.snapMark = mark
	return s.pruneLocked()
}

func (s *Store) pruneLocked() error {
	for len(s.snaps) > keepSnapshots {
		if err := s.fs.Remove(filepath.Join(s.dir, s.snaps[0].name)); err != nil {
			return err
		}
		s.snaps = s.snaps[1:]
	}
	oldest := s.snaps[0].rev
	for len(s.segs) > 1 && s.segs[1].firstRev-1 <= oldest {
		if s.seg != nil && s.seg.info == s.segs[0] {
			break
		}
		if err := s.fs.Remove(filepath.Join(s.dir, s.segs[0].name)); err != nil {
			return err
		}
		s.segs = s.segs[1:]
	}
	return s.fs.SyncDir(s.dir)
}

// PruneTombstones forgets tombstones at or below upTo; they stay needed only until every consumer has passed them.
func (s *Store) PruneTombstones(upTo uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.head = s.head.withoutTombstones(upTo)
	s.cur.Store(s.cur.Load().withoutTombstones(upTo))
}

// Verify recomputes the partition hashes and counts from the rows.
func (s *Store) Verify() error {
	v := s.cur.Load()
	key, ok := s.keys.Key(v.keyEpoch)
	if !ok {
		return fmt.Errorf("%w: %d", ErrKey, v.keyEpoch)
	}
	return v.verify(newRowHasher(key))
}

// Record is one raw log record as sent to followers.
type Record struct {
	Type     byte
	KeyEpoch uint32
	Term     uint64
	Rev      uint64
	Commit   uint64
	Payload  []byte
	Chain    [32]byte
}

// Records streams the committed records from revision from up to the current head.
func (s *Store) Records(from uint64, fn func(Record) error) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	segs := append([]segInfo(nil), s.segs...)
	head := s.head.rev
	s.mu.Unlock()
	if from == 0 {
		from = 1
	}
	if from > head {
		return nil
	}
	if len(segs) == 0 || segs[0].firstRev > from {
		return ErrGap
	}
	for i, si := range segs {
		if i+1 < len(segs) && segs[i+1].firstRev <= from {
			continue
		}
		if si.firstRev > head {
			break
		}
		path := filepath.Join(s.dir, si.name)
		f, err := s.fs.OpenFile(path, os.O_RDONLY, 0)
		if err != nil {
			return err
		}
		size, err := f.Size()
		if err != nil {
			_ = f.Close()
			return err
		}
		br := bufio.NewReaderSize(io.NewSectionReader(f, headerSize, size-headerSize), 256<<10)
		off := int64(headerSize)
		for {
			rec, n, err := readRecord(br, size-off)
			if err == errEnd || err == errTorn {
				break
			}
			off += n
			if rec.rev > head {
				break
			}
			if rec.rev < from {
				continue
			}
			if err := fn(Record{rec.typ, rec.keyEpoch, rec.term, rec.rev, rec.commit, rec.payload, rec.chain}); err != nil {
				_ = f.Close()
				return err
			}
		}
		_ = f.Close()
	}
	return nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	s.snapWG.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if s.seg != nil {
		err = s.seg.f.Close()
		s.seg = nil
	}
	if cerr := s.dirLock.Close(); err == nil {
		err = cerr
	}
	return err
}
