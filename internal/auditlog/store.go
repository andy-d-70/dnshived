// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package auditlog

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"dnshived/internal/dnsstore/vfs"
)

// The store keeps the cluster's audit entries as an append-only set: every entry has a 16-byte id, the same id on
// every core means the same entry, and an entry is never changed or removed. Cores merge by union.
//
// Segment file audit-<number as 16 hex>.seg: a 64-byte header, then records, all little-endian.
//   header: "DHAL", major u8, minor u8, 2 reserved, segment number u64, key id 8 bytes, 36 reserved, CRC32C u32
//   record: length u32 (of what follows the CRC), CRC32C u32, id 16 bytes, chain 32 bytes, body
// chain = HMAC(key, previous chain || id || body), starting at HMAC(key, segment number) in every segment, so damage
// stays inside one segment. Nothing in a segment is ever overwritten: after damage or an interrupted write the
// verified records before it are served, the rest stays in place, and new entries go to a new segment.

type ID [16]byte

var (
	ErrClosed  = errors.New("auditlog: closed")
	ErrVersion = errors.New("auditlog: unsupported format version")
	ErrInvalid = errors.New("auditlog: invalid entry")
	ErrCorrupt = errors.New("auditlog: corrupt")
)

const (
	segMagic       = "DHAL"
	verMajor       = 1
	verMinor       = 0
	headerSize     = 64
	recHead        = 8
	chainSize      = 32
	recFixed       = 16 + chainSize
	MaxBody        = 64 << 10
	defaultSegSize = 16 << 20
	minSegSize     = 4 << 10
	numShards      = 256
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

type Options struct {
	FS          vfs.FS
	Key         []byte
	SegmentSize int64
}

type loc struct {
	seg uint32
	off uint32
}

type segFile struct {
	no   uint64
	name string
	f    vfs.File
	end  int64
}

// Store is safe for concurrent use. Every method holds the store lock across its own I/O; writes are rare (one per
// operator action) and the lock keeps the single-writer rule simple.
type Store struct {
	mu      sync.Mutex
	fs      vfs.FS
	dir     string
	key     []byte
	keyID   [8]byte
	segSize int64
	lock    io.Closer

	segs   []*segFile
	cur    *segFile
	curIdx uint32
	chain  [chainSize]byte
	maxNo  uint64
	index  map[ID]loc
	hashes [numShards][32]byte
	notes  []string
	failed error
	closed bool
}

func segName(no uint64) string { return fmt.Sprintf("audit-%016x.seg", no) }

// Open opens or creates the store in dir, which must be accessible to its owner only.
func Open(dir string, o Options) (*Store, error) {
	if o.FS == nil {
		o.FS = vfs.OS{}
	}
	if len(o.Key) == 0 {
		return nil, fmt.Errorf("%w: no key", ErrInvalid)
	}
	if o.SegmentSize == 0 {
		o.SegmentSize = defaultSegSize
	}
	if o.SegmentSize < minSegSize || o.SegmentSize > 1<<31 {
		return nil, fmt.Errorf("%w: segment size %d", ErrInvalid, o.SegmentSize)
	}
	if err := o.FS.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("auditlog: create %s: %w", dir, err)
	}
	mode, err := o.FS.Mode(dir)
	if err != nil {
		return nil, fmt.Errorf("auditlog: %s: %w", dir, err)
	}
	if mode.Perm()&0o077 != 0 {
		return nil, fmt.Errorf("auditlog: %s is accessible to others (%v)", dir, mode.Perm())
	}
	lk, err := o.FS.Lock(filepath.Join(dir, "LOCK"))
	if err != nil {
		return nil, fmt.Errorf("auditlog: lock %s: %w", dir, err)
	}
	s := &Store{fs: o.FS, dir: dir, key: append([]byte(nil), o.Key...), segSize: o.SegmentSize, lock: lk, index: map[ID]loc{}}
	s.keyID = s.computeKeyID()
	if err := s.load(); err != nil {
		s.closeFiles()
		_ = lk.Close()
		return nil, err
	}
	return s, nil
}

type staged struct {
	id  ID
	off int64
	sum [32]byte
}

type scanResult struct {
	end        int64
	chain      [chainSize]byte
	entries    []staged
	appendable bool
	blank      bool
	note       string
}

func (s *Store) load() error {
	names, err := s.fs.ReadDir(s.dir)
	if err != nil {
		return fmt.Errorf("auditlog: read %s: %w", s.dir, err)
	}
	var nos []uint64
	for _, n := range names {
		if !strings.HasPrefix(n, "audit-") || !strings.HasSuffix(n, ".seg") {
			continue
		}
		var no uint64
		if _, err := fmt.Sscanf(n, "audit-%016x.seg", &no); err != nil || no == 0 || segName(no) != n {
			continue
		}
		nos = append(nos, no)
	}
	sort.Slice(nos, func(i, j int) bool { return nos[i] < nos[j] })
	var last scanResult
	for i, no := range nos {
		sf := &segFile{no: no, name: segName(no)}
		sf.f, err = s.fs.OpenFile(filepath.Join(s.dir, sf.name), os.O_RDWR, 0o600)
		if err != nil {
			return fmt.Errorf("auditlog: open %s: %w", sf.name, err)
		}
		idx := uint32(len(s.segs))
		s.segs = append(s.segs, sf)
		s.maxNo = no
		res, err := s.scan(sf)
		if err != nil {
			return err
		}
		if res.blank && i == len(nos)-1 {
			if err := writeHeader(sf.f, s.header(no)); err != nil {
				return fmt.Errorf("auditlog: complete header of %s: %w", sf.name, err)
			}
			res = scanResult{end: headerSize, chain: s.segStart(no), appendable: true}
		}
		sf.end = res.end
		if res.note != "" {
			s.notes = append(s.notes, res.note)
		}
		for _, e := range res.entries {
			if _, held := s.index[e.id]; held {
				continue
			}
			s.index[e.id] = loc{seg: idx, off: uint32(e.off)}
			xorInto(&s.hashes[e.id[0]], e.sum)
		}
		last = res
	}
	if n := len(s.segs); n > 0 && last.appendable {
		s.cur, s.curIdx, s.chain = s.segs[n-1], uint32(n-1), last.chain
		return nil
	}
	return s.newSegment()
}

// scan verifies one segment and stages its entries. It never changes the file.
func (s *Store) scan(sf *segFile) (scanResult, error) {
	size, err := sf.f.Size()
	if err != nil {
		return scanResult{}, fmt.Errorf("auditlog: size of %s: %w", sf.name, err)
	}
	data := make([]byte, size)
	if _, err := sf.f.ReadAt(data, 0); err != nil && !errors.Is(err, io.EOF) {
		return scanResult{}, fmt.Errorf("auditlog: read %s: %w", sf.name, err)
	}
	want := s.header(sf.no)
	if allZero(data) || (size < headerSize && bytes.HasPrefix(want, data)) {
		return scanResult{blank: true}, nil
	}
	if size < headerSize {
		return scanResult{note: fmt.Sprintf("%s: short header, kept in place, not served", sf.name)}, nil
	}
	h := data[:headerSize]
	switch {
	case string(h[:4]) != segMagic || crc32.Checksum(h[:headerSize-4], castagnoli) != binary.LittleEndian.Uint32(h[headerSize-4:]):
		return scanResult{note: fmt.Sprintf("%s: damaged header, kept in place, not served", sf.name)}, nil
	case h[4] != verMajor:
		return scanResult{}, fmt.Errorf("%w: %s has format %d.%d", ErrVersion, sf.name, h[4], h[5])
	case binary.LittleEndian.Uint64(h[8:]) != sf.no:
		return scanResult{note: fmt.Sprintf("%s: segment number does not match its name, kept in place, not served", sf.name)}, nil
	case !bytes.Equal(h[16:24], s.keyID[:]):
		return scanResult{note: fmt.Sprintf("%s: written with another cluster key, kept in place, not served", sf.name)}, nil
	}
	res := scanResult{end: headerSize, chain: s.segStart(sf.no), appendable: true}
	for res.end < size {
		id, body, next, ok := s.parse(data, res.end, res.chain)
		if !ok {
			if !allZero(data[res.end:]) {
				res.appendable = false
				res.note = fmt.Sprintf("%s: %d bytes after offset %d unreadable (interrupted write or damage), kept in place", sf.name, size-res.end, res.end)
			}
			break
		}
		copy(res.chain[:], data[res.end+recHead+16:res.end+recHead+recFixed])
		res.entries = append(res.entries, staged{id: id, off: res.end, sum: entrySum(id, body)})
		res.end = next
	}
	return res, nil
}

func (s *Store) parse(data []byte, off int64, prev [chainSize]byte) (id ID, body []byte, next int64, ok bool) {
	size := int64(len(data))
	if off+recHead > size {
		return id, nil, 0, false
	}
	n := int64(binary.LittleEndian.Uint32(data[off:]))
	end := off + recHead + n
	if n < recFixed+1 || n > recFixed+MaxBody || end > size {
		return id, nil, 0, false
	}
	rest := data[off+recHead : end]
	if crc32.Checksum(rest, castagnoli) != binary.LittleEndian.Uint32(data[off+4:]) {
		return id, nil, 0, false
	}
	copy(id[:], rest[:16])
	body = rest[recFixed:]
	link := s.link(prev, id, body)
	if !hmac.Equal(link[:], rest[16:recFixed]) {
		return id, nil, 0, false
	}
	return id, body, end, true
}

func (s *Store) computeKeyID() [8]byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte("dnshived-auditlog-key-id"))
	var out [8]byte
	copy(out[:], m.Sum(nil))
	return out
}

func (s *Store) segStart(no uint64) [chainSize]byte {
	m := hmac.New(sha256.New, s.key)
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], no)
	m.Write([]byte("dnshived-auditlog-segment"))
	m.Write(b[:])
	var out [chainSize]byte
	m.Sum(out[:0])
	return out
}

func (s *Store) link(prev [chainSize]byte, id ID, body []byte) [chainSize]byte {
	m := hmac.New(sha256.New, s.key)
	m.Write(prev[:])
	m.Write(id[:])
	m.Write(body)
	var out [chainSize]byte
	m.Sum(out[:0])
	return out
}

func (s *Store) header(no uint64) []byte {
	h := make([]byte, headerSize)
	copy(h, segMagic)
	h[4], h[5] = verMajor, verMinor
	binary.LittleEndian.PutUint64(h[8:], no)
	copy(h[16:24], s.keyID[:])
	binary.LittleEndian.PutUint32(h[headerSize-4:], crc32.Checksum(h[:headerSize-4], castagnoli))
	return h
}

func writeHeader(f vfs.File, h []byte) error {
	if err := f.Truncate(0); err != nil {
		return err
	}
	if _, err := f.WriteAt(h, 0); err != nil {
		return err
	}
	return f.Sync()
}

func entrySum(id ID, body []byte) [32]byte {
	h := sha256.New()
	h.Write(id[:])
	h.Write(body)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

func xorInto(dst *[32]byte, src [32]byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func (s *Store) newSegment() error {
	no := s.maxNo + 1
	sf := &segFile{no: no, name: segName(no), end: headerSize}
	f, err := s.fs.OpenFile(filepath.Join(s.dir, sf.name), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("auditlog: create %s: %w", sf.name, err)
	}
	if _, err := f.WriteAt(s.header(no), 0); err != nil {
		_ = f.Close()
		return fmt.Errorf("auditlog: write %s: %w", sf.name, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("auditlog: sync %s: %w", sf.name, err)
	}
	if err := s.fs.SyncDir(s.dir); err != nil {
		_ = f.Close()
		return fmt.Errorf("auditlog: sync %s: %w", s.dir, err)
	}
	sf.f = f
	s.maxNo = no
	s.segs = append(s.segs, sf)
	s.cur, s.curIdx, s.chain = sf, uint32(len(s.segs)-1), s.segStart(no)
	return nil
}

// StoredEntry is one audit line as stored: its id and its body (one line of JSON, no newline).
type StoredEntry struct {
	ID   ID
	Body []byte
}

// Append adds the entries the store does not hold yet and returns how many were new, once they are on disk. An entry
// already held is skipped, so repeating an append or receiving the same entry from several cores is harmless.
func (s *Store) Append(entries []StoredEntry) (int, error) {
	for _, e := range entries {
		if len(e.Body) == 0 || len(e.Body) > MaxBody || bytes.IndexByte(e.Body, '\n') >= 0 {
			return 0, fmt.Errorf("%w: body of %x", ErrInvalid, e.ID)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, ErrClosed
	}
	if s.failed != nil {
		return 0, s.failed
	}
	var (
		buf   []byte
		todo  []staged
		added int
		start = s.cur.end
		chain = s.chain
		seen  = map[ID]bool{}
	)
	flush := func() error {
		if len(buf) == 0 {
			return nil
		}
		if _, err := s.cur.f.WriteAt(buf, start); err != nil {
			return s.fail(err)
		}
		if err := s.cur.f.SyncData(); err != nil {
			return s.fail(err)
		}
		for _, p := range todo {
			s.index[p.id] = loc{seg: s.curIdx, off: uint32(p.off)}
			xorInto(&s.hashes[p.id[0]], p.sum)
		}
		added += len(todo)
		s.cur.end, s.chain = start+int64(len(buf)), chain
		start, buf, todo = s.cur.end, buf[:0], todo[:0]
		return nil
	}
	for _, e := range entries {
		if _, held := s.index[e.ID]; held || seen[e.ID] {
			continue
		}
		size := int64(recHead + recFixed + len(e.Body))
		if fill := start + int64(len(buf)); fill+size > s.segSize && fill > headerSize {
			if err := flush(); err != nil {
				return added, err
			}
			if err := s.newSegment(); err != nil {
				return added, s.fail(err)
			}
			start, chain = s.cur.end, s.chain
		}
		seen[e.ID] = true
		off := start + int64(len(buf))
		chain = s.link(chain, e.ID, e.Body)
		var head [recHead]byte
		binary.LittleEndian.PutUint32(head[:], uint32(recFixed+len(e.Body)))
		rec := len(buf) + recHead
		buf = append(buf, head[:]...)
		buf = append(buf, e.ID[:]...)
		buf = append(buf, chain[:]...)
		buf = append(buf, e.Body...)
		binary.LittleEndian.PutUint32(buf[rec-4:], crc32.Checksum(buf[rec:], castagnoli))
		todo = append(todo, staged{id: e.ID, off: off, sum: entrySum(e.ID, e.Body)})
	}
	if err := flush(); err != nil {
		return added, err
	}
	return added, nil
}

func (s *Store) fail(err error) error {
	s.failed = fmt.Errorf("auditlog: write failed, the store must be reopened: %w", err)
	return s.failed
}

func (s *Store) readLocked(l loc) ([]byte, error) {
	sf := s.segs[l.seg]
	var head [recHead]byte
	if _, err := sf.f.ReadAt(head[:], int64(l.off)); err != nil {
		return nil, fmt.Errorf("auditlog: read %s at %d: %w", sf.name, l.off, err)
	}
	n := binary.LittleEndian.Uint32(head[:])
	if n < recFixed+1 || n > recFixed+MaxBody {
		return nil, fmt.Errorf("%w: %s offset %d: length %d", ErrCorrupt, sf.name, l.off, n)
	}
	rest := make([]byte, n)
	if _, err := sf.f.ReadAt(rest, int64(l.off)+recHead); err != nil {
		return nil, fmt.Errorf("auditlog: read %s at %d: %w", sf.name, l.off, err)
	}
	if got, want := crc32.Checksum(rest, castagnoli), binary.LittleEndian.Uint32(head[4:]); got != want {
		return nil, fmt.Errorf("%w: %s offset %d: checksum %08x, want %08x", ErrCorrupt, sf.name, l.off, got, want)
	}
	return rest[recFixed:], nil
}

// Get returns the entry's body (a copy).
func (s *Store) Get(id ID) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, false, ErrClosed
	}
	l, ok := s.index[id]
	if !ok {
		return nil, false, nil
	}
	b, err := s.readLocked(l)
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}

func (s *Store) Has(id ID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.index[id]
	return ok
}

func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.index)
}

// Hashes returns one content hash per shard (first id byte): the XOR of sha256(id || body) over its entries. Two
// stores with equal hashes hold the same entries, whatever order they were added in.
func (s *Store) Hashes() [numShards][32]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hashes
}

// IDs returns the ids of one shard, sorted.
func (s *Store) IDs(shard byte) []ID {
	s.mu.Lock()
	var out []ID
	for id := range s.index {
		if id[0] == shard {
			out = append(out, id)
		}
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i][:], out[j][:]) < 0 })
	return out
}

// Notes lists what the last open found unreadable; the bytes are kept in place.
func (s *Store) Notes() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.notes...)
}

// Each calls fn for every entry in the order this core stored them. The body is valid only during the call, and fn
// must not call the store (it runs under the store lock).
func (s *Store) Each(fn func(id ID, body []byte) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	for idx, sf := range s.segs {
		if sf.end <= headerSize {
			continue
		}
		data := make([]byte, sf.end)
		if _, err := sf.f.ReadAt(data, 0); err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("auditlog: read %s: %w", sf.name, err)
		}
		for off := int64(headerSize); off < sf.end; {
			n := int64(binary.LittleEndian.Uint32(data[off:]))
			end := off + recHead + n
			if n < recFixed+1 || end > sf.end {
				return fmt.Errorf("%w: %s offset %d", ErrCorrupt, sf.name, off)
			}
			rest := data[off+recHead : end]
			if crc32.Checksum(rest, castagnoli) != binary.LittleEndian.Uint32(data[off+4:]) {
				return fmt.Errorf("%w: %s offset %d: checksum", ErrCorrupt, sf.name, off)
			}
			var id ID
			copy(id[:], rest[:16])
			if l, ok := s.index[id]; ok && l.seg == uint32(idx) && int64(l.off) == off {
				if err := fn(id, rest[recFixed:]); err != nil {
					return err
				}
			}
			off = end
		}
	}
	return nil
}

// Bytes is the size of the verified data in all segments.
func (s *Store) Bytes() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for _, sf := range s.segs {
		n += sf.end
	}
	return n
}

// Export writes every entry as one line, oldest "ts" first; entries without a readable ts come first, by id.
func (s *Store) Export(w io.Writer) error {
	type item struct {
		ts int64
		id ID
	}
	var items []item
	if err := s.Each(func(id ID, body []byte) error {
		var probe struct {
			TS time.Time `json:"ts"`
		}
		it := item{id: id}
		if json.Unmarshal(body, &probe) == nil && !probe.TS.IsZero() {
			it.ts = probe.TS.UnixNano()
		}
		items = append(items, it)
		return nil
	}); err != nil {
		return err
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].ts != items[j].ts {
			return items[i].ts < items[j].ts
		}
		return bytes.Compare(items[i].id[:], items[j].id[:]) < 0
	})
	bw := bufio.NewWriter(w)
	for _, it := range items {
		body, ok, err := s.Get(it.id)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if _, err := bw.Write(body); err != nil {
			return err
		}
		if err := bw.WriteByte('\n'); err != nil {
			return err
		}
	}
	return bw.Flush()
}

func (s *Store) closeFiles() {
	for _, sf := range s.segs {
		if sf.f != nil {
			_ = sf.f.Close()
		}
	}
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.closeFiles()
	return s.lock.Close()
}
