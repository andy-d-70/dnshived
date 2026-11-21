// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsstore

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"

	"dnshived/internal/dnsstore/vfs"
)

const (
	snapBlock     = 64 << 10
	maxSnapBlock  = 1 << 20
	snapSyncEvery = 8 << 20
	footerMagic   = "DHSF"
	footerFixed   = 4 + 8 + 8 + 4 + chainSize + 8 + 8 + 8
	footerSize    = footerFixed + numShards*chainSize + 32 + 4
	entryRow      = 1
	entryTomb     = 2
)

type seqWriter struct {
	f         vfs.File
	off       int64
	sinceSync int64
}

func (w *seqWriter) Write(p []byte) (int, error) {
	n, err := w.f.WriteAt(p, w.off)
	w.off += int64(n)
	w.sinceSync += int64(n)
	if err == nil && w.sinceSync >= snapSyncEvery {
		err = w.f.SyncData()
		w.sinceSync = 0
	}
	return n, err
}

type snapEntry struct {
	key  rowKey
	rev  uint64
	body []byte
	tomb bool
}

func sortedEntries(v *View) []snapEntry {
	out := make([]snapEntry, 0, v.rows+v.tombs)
	for _, sh := range v.shards {
		if sh == nil {
			continue
		}
		for k, r := range sh.rows {
			out = append(out, snapEntry{key: k, rev: r.rev, body: r.body})
		}
		for k, rev := range sh.tombs {
			out = append(out, snapEntry{key: k, rev: rev, tomb: true})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.key.typ != b.key.typ {
			return a.key.typ < b.key.typ
		}
		if c := bytes.Compare(a.key.id[:], b.key.id[:]); c != 0 {
			return c < 0
		}
		return !a.tomb && b.tomb
	})
	return out
}

func snapName(rev uint64) string { return fmt.Sprintf("snap-%016x.snap", rev) }

// writeSnapshot writes v atomically: temp file, fsync, rename, directory fsync.
func writeSnapshot(fs vfs.FS, dir string, v *View, id ID) error {
	tmp := filepath.Join(dir, "snap.tmp")
	_ = fs.Remove(tmp)
	f, err := fs.OpenFile(tmp, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	sw := &seqWriter{f: f}
	bw := bufio.NewWriterSize(sw, 256<<10)
	if _, err := bw.Write(encodeHeader(header{ftype: ftSnap, major: verMajor, minor: verMinor, storeID: id, firstRev: v.rev})); err != nil {
		return err
	}
	var blocks uint64
	buf := make([]byte, 0, snapBlock+MaxRow+64)
	flush := func() error {
		if len(buf) == 0 {
			return nil
		}
		var hd [8]byte
		le.PutUint32(hd[:], uint32(len(buf)))
		le.PutUint32(hd[4:], crc32.Checksum(buf, castagnoli))
		if _, err := bw.Write(hd[:]); err != nil {
			return err
		}
		if _, err := bw.Write(buf); err != nil {
			return err
		}
		buf = buf[:0]
		blocks++
		return nil
	}
	for _, e := range sortedEntries(v) {
		if e.tomb {
			buf = append(buf, entryTomb, e.key.typ)
		} else {
			buf = append(buf, entryRow, e.key.typ)
		}
		buf = append(buf, e.key.id[:]...)
		buf = le.AppendUint64(buf, e.rev)
		if !e.tomb {
			buf = binary.AppendUvarint(buf, uint64(len(e.body)))
			buf = append(buf, e.body...)
		}
		if len(buf) >= snapBlock {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := flush(); err != nil {
		return err
	}
	footerOff := sw.off + int64(bw.Buffered())
	ft := make([]byte, 0, footerSize+8)
	ft = append(ft, footerMagic...)
	ft = le.AppendUint64(ft, v.rev)
	ft = le.AppendUint64(ft, v.term)
	ft = le.AppendUint32(ft, v.keyEpoch)
	ft = append(ft, v.chain[:]...)
	ft = le.AppendUint64(ft, uint64(v.rows))
	ft = le.AppendUint64(ft, uint64(v.tombs))
	ft = le.AppendUint64(ft, blocks)
	for i := range v.hashes {
		ft = append(ft, v.hashes[i][:]...)
	}
	m := v.Manifest()
	ft = append(ft, m[:]...)
	ft = le.AppendUint32(ft, crc32.Checksum(ft, castagnoli))
	ft = le.AppendUint64(ft, uint64(footerOff))
	if _, err := bw.Write(ft); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := fs.Rename(tmp, filepath.Join(dir, snapName(v.rev))); err != nil {
		return err
	}
	return fs.SyncDir(dir)
}

type snapFooter struct {
	rev, term uint64
	keyEpoch  uint32
	chain     [chainSize]byte
	rows      uint64
	tombs     uint64
	blocks    uint64
	hashes    [numShards][chainSize]byte
	manifest  [32]byte
}

func readFooter(f vfs.File, size int64, name string) (snapFooter, int64, error) {
	var ft snapFooter
	if size < headerSize+footerSize+8 {
		return ft, 0, corrupt(name, 0, "file of %d bytes is too short", size)
	}
	var tail [8]byte
	if _, err := f.ReadAt(tail[:], size-8); err != nil {
		return ft, 0, err
	}
	off := int64(le.Uint64(tail[:]))
	if off < headerSize || off != size-8-footerSize {
		return ft, 0, corrupt(name, size-8, "footer offset %d", off)
	}
	b := make([]byte, footerSize)
	if _, err := f.ReadAt(b, off); err != nil {
		return ft, 0, err
	}
	if string(b[:4]) != footerMagic {
		return ft, 0, corrupt(name, off, "bad footer magic")
	}
	if crc32.Checksum(b[:footerSize-4], castagnoli) != le.Uint32(b[footerSize-4:]) {
		return ft, 0, corrupt(name, off, "footer checksum mismatch")
	}
	ft.rev, ft.term, ft.keyEpoch = le.Uint64(b[4:]), le.Uint64(b[12:]), le.Uint32(b[20:])
	copy(ft.chain[:], b[24:56])
	ft.rows, ft.tombs, ft.blocks = le.Uint64(b[56:]), le.Uint64(b[64:]), le.Uint64(b[72:])
	p := footerFixed
	for i := range ft.hashes {
		copy(ft.hashes[i][:], b[p:p+chainSize])
		p += chainSize
	}
	copy(ft.manifest[:], b[p:p+32])
	return ft, off, nil
}

// loadSnapshot reads and fully verifies a snapshot; any mismatch is ErrCorrupt.
func loadSnapshot(fs vfs.FS, path string, id ID, keys Keys) (*View, error) {
	f, err := fs.OpenFile(path, 0, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	size, err := f.Size()
	if err != nil {
		return nil, err
	}
	hb := make([]byte, headerSize)
	if _, err := f.ReadAt(hb, 0); err != nil {
		return nil, corrupt(path, 0, "header: %v", err)
	}
	h, err := decodeHeader(hb, path)
	if err != nil {
		return nil, err
	}
	if h.ftype != ftSnap {
		return nil, corrupt(path, 4, "not a snapshot")
	}
	if h.storeID != id {
		return nil, fmt.Errorf("%w: %s", ErrStoreID, path)
	}
	ft, footerOff, err := readFooter(f, size, path)
	if err != nil {
		return nil, err
	}
	if ft.rev != h.firstRev {
		return nil, corrupt(path, 0, "revision %d differs from the footer's %d", h.firstRev, ft.rev)
	}
	key, ok := keys.Key(ft.keyEpoch)
	if !ok {
		return nil, fmt.Errorf("%w: epoch %d in %s", ErrKey, ft.keyEpoch, path)
	}
	hasher := newRowHasher(key)
	v := &View{rev: ft.rev, term: ft.term, chain: ft.chain, keyEpoch: ft.keyEpoch}
	br := bufio.NewReaderSize(io.NewSectionReader(f, headerSize, footerOff-headerSize), 256<<10)
	off := int64(headerSize)
	var prev snapEntry
	havePrev := false
	for b := uint64(0); b < ft.blocks; b++ {
		var hd [8]byte
		if _, err := io.ReadFull(br, hd[:]); err != nil {
			return nil, corrupt(path, off, "block header: %v", err)
		}
		n := int64(le.Uint32(hd[:]))
		if n == 0 || n > maxSnapBlock || off+8+n > footerOff {
			return nil, corrupt(path, off, "block length %d", n)
		}
		blk := make([]byte, n)
		if _, err := io.ReadFull(br, blk); err != nil {
			return nil, corrupt(path, off, "block body: %v", err)
		}
		if crc32.Checksum(blk, castagnoli) != le.Uint32(hd[4:]) {
			return nil, corrupt(path, off, "block checksum mismatch")
		}
		r := &reader{b: blk}
		for len(r.b) > 0 {
			head := r.take(2 + 16 + 8)
			if head == nil {
				return nil, corrupt(path, off, "short entry")
			}
			e := snapEntry{tomb: head[0] == entryTomb, rev: le.Uint64(head[18:])}
			if head[0] != entryRow && head[0] != entryTomb || head[1] == 0 {
				return nil, corrupt(path, off, "entry kind %d type %d", head[0], head[1])
			}
			e.key.typ = head[1]
			copy(e.key.id[:], head[2:18])
			if !e.tomb {
				l := r.uvarint()
				if l > MaxRow {
					return nil, corrupt(path, off, "row of %d bytes", l)
				}
				e.body = append([]byte(nil), r.take(int(l))...)
			}
			if r.err != nil {
				return nil, corrupt(path, off, "short entry body")
			}
			if havePrev && !snapLess(prev, e) {
				return nil, corrupt(path, off, "entries out of order")
			}
			prev, havePrev = e, true
			si := e.key.id[0]
			sh := v.shards[si]
			if sh == nil {
				sh = &shard{rows: map[rowKey]rowVal{}, tombs: map[rowKey]uint64{}}
				v.shards[si] = sh
			}
			if e.tomb {
				sh.tombs[e.key] = e.rev
				v.tombs++
			} else {
				sh.rows[e.key] = rowVal{rev: e.rev, body: e.body}
				xorInto(&v.hashes[si], hasher.sum(e.key, e.rev, e.body))
				v.rows++
			}
		}
		off += 8 + n
	}
	if off != footerOff {
		return nil, corrupt(path, off, "blocks end before the footer")
	}
	if uint64(v.rows) != ft.rows || uint64(v.tombs) != ft.tombs {
		return nil, corrupt(path, footerOff, "counts rows=%d/%d tombstones=%d/%d", v.rows, ft.rows, v.tombs, ft.tombs)
	}
	if v.hashes != ft.hashes || v.Manifest() != ft.manifest {
		return nil, corrupt(path, footerOff, "partition hashes differ from the rows")
	}
	return v, nil
}

func snapLess(a, b snapEntry) bool {
	if a.key.typ != b.key.typ {
		return a.key.typ < b.key.typ
	}
	if c := bytes.Compare(a.key.id[:], b.key.id[:]); c != 0 {
		return c < 0
	}
	return !a.tomb && b.tomb
}
