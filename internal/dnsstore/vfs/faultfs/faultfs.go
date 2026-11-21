// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package faultfs is an in-memory vfs.FS that loses unsynced bytes, tears writes and crashes at a chosen operation.
package faultfs

import (
	"errors"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"dnshived/internal/dnsstore/vfs"
)

var (
	ErrCrashed  = errors.New("faultfs: crashed")
	ErrInjected = errors.New("faultfs: injected I/O error")
)

const sector = 512

type node struct {
	vol []byte
	dur []byte
}

type FS struct {
	mu       sync.Mutex
	files    map[string]*node
	durNames map[string]*node
	locks    map[string]bool
	rng      *rand.Rand
	gen      int
	ops      int
	crashAt  int
	torn     bool
	crashed  bool
	syncs    int
	failSync int
}

func New(seed int64) *FS {
	return &FS{
		files:    map[string]*node{},
		durNames: map[string]*node{},
		locks:    map[string]bool{},
		rng:      rand.New(rand.NewSource(seed)),
	}
}

func (f *FS) Ops() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ops
}

func (f *FS) SetCrashAt(n int, torn bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.crashAt, f.torn = n, torn
}

func (f *FS) InjectSyncError(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.syncs, f.failSync = 0, n
}

func (f *FS) Crashed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.crashed
}

// tick counts a mutating operation; it reports true when this operation is the crash point.
func (f *FS) tick() (crash bool, err error) {
	if f.crashed {
		return false, ErrCrashed
	}
	f.ops++
	if f.crashAt > 0 && f.ops == f.crashAt {
		f.crashed = true
		return true, ErrCrashed
	}
	return false, nil
}

// Crash simulates a power cut and reboot: unsynced bytes are lost or kept sector by sector, unsynced directory changes vanish.
func (f *FS) Crash() {
	f.mu.Lock()
	defer f.mu.Unlock()
	next := map[string]*node{}
	for name, n := range f.durNames {
		n.vol = f.survive(n)
		n.dur = append([]byte(nil), n.vol...)
		next[name] = n
	}
	f.files = next
	f.durNames = copyNames(next)
	f.locks = map[string]bool{}
	f.gen++
	f.crashed, f.crashAt, f.ops = false, 0, 0
}

func copyNames(m map[string]*node) map[string]*node {
	out := make(map[string]*node, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func (f *FS) survive(n *node) []byte {
	size := len(n.dur)
	if len(n.vol) > size {
		size += f.rng.Intn(len(n.vol) - size + 1)
	}
	out := make([]byte, size)
	for off := 0; off < size; off += sector {
		end := min(off+sector, size)
		src := n.dur
		if f.rng.Intn(2) == 0 {
			src = n.vol
		}
		for i := off; i < end; i++ {
			if i < len(src) {
				out[i] = src[i]
			} else if i < len(n.vol) {
				out[i] = n.vol[i]
			}
		}
	}
	return out
}

// Raw returns a copy of the current (volatile) content of a file.
func (f *FS) Raw(name string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, ok := f.files[filepath.Clean(name)]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), n.vol...), true
}

// Poke overwrites bytes in both the volatile and the durable copy of a file, to model silent corruption.
func (f *FS) Poke(name string, off int, b []byte) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, ok := f.files[filepath.Clean(name)]
	if !ok || off+len(b) > len(n.vol) {
		return false
	}
	copy(n.vol[off:], b)
	if off+len(b) <= len(n.dur) {
		copy(n.dur[off:], b)
	}
	return true
}

func (f *FS) Names(dir string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.list(dir)
}

func (f *FS) list(dir string) []string {
	dir = filepath.Clean(dir)
	var out []string
	for name := range f.files {
		if filepath.Dir(name) == dir {
			out = append(out, filepath.Base(name))
		}
	}
	sort.Strings(out)
	return out
}

type file struct {
	fs   *FS
	n    *node
	name string
	gen  int
}

func (f *FS) OpenFile(name string, flag int, perm os.FileMode) (vfs.File, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	name = filepath.Clean(name)
	n, ok := f.files[name]
	switch {
	case !ok && flag&os.O_CREATE == 0:
		return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrNotExist}
	case ok && flag&os.O_CREATE != 0 && flag&os.O_EXCL != 0:
		return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrExist}
	case !ok:
		if crash, err := f.tick(); err != nil || crash {
			return nil, ErrCrashed
		}
		n = &node{}
		f.files[name] = n
	case flag&os.O_TRUNC != 0:
		if crash, err := f.tick(); err != nil || crash {
			return nil, ErrCrashed
		}
		n.vol = nil
	}
	if f.crashed {
		return nil, ErrCrashed
	}
	return &file{fs: f, n: n, name: name, gen: f.gen}, nil
}

func (f *FS) Rename(oldpath, newpath string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	oldpath, newpath = filepath.Clean(oldpath), filepath.Clean(newpath)
	if crash, err := f.tick(); err != nil || crash {
		return ErrCrashed
	}
	n, ok := f.files[oldpath]
	if !ok {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: os.ErrNotExist}
	}
	delete(f.files, oldpath)
	f.files[newpath] = n
	return nil
}

func (f *FS) Remove(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	name = filepath.Clean(name)
	if crash, err := f.tick(); err != nil || crash {
		return ErrCrashed
	}
	if _, ok := f.files[name]; !ok {
		return &os.PathError{Op: "remove", Path: name, Err: os.ErrNotExist}
	}
	delete(f.files, name)
	return nil
}

func (f *FS) ReadDir(dir string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.crashed {
		return nil, ErrCrashed
	}
	return f.list(dir), nil
}

func (f *FS) MkdirAll(string, os.FileMode) error { return nil }

func (f *FS) Mode(string) (os.FileMode, error) { return os.ModeDir | 0o700, nil }

func (f *FS) SyncDir(dir string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	dir = filepath.Clean(dir)
	if crash, err := f.tick(); err != nil || crash {
		return ErrCrashed
	}
	for name := range f.durNames {
		if filepath.Dir(name) == dir {
			delete(f.durNames, name)
		}
	}
	for name, n := range f.files {
		if filepath.Dir(name) == dir {
			f.durNames[name] = n
		}
	}
	return nil
}

type lock struct {
	fs   *FS
	name string
}

func (l *lock) Close() error {
	l.fs.mu.Lock()
	defer l.fs.mu.Unlock()
	delete(l.fs.locks, l.name)
	return nil
}

func (f *FS) Lock(name string) (io.Closer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	name = filepath.Clean(name)
	if f.locks[name] {
		return nil, vfs.ErrLocked
	}
	f.locks[name] = true
	return &lock{fs: f, name: name}, nil
}

func (h *file) live() error {
	if h.fs.crashed || h.gen != h.fs.gen {
		return ErrCrashed
	}
	return nil
}

func (h *file) ReadAt(p []byte, off int64) (int, error) {
	h.fs.mu.Lock()
	defer h.fs.mu.Unlock()
	if err := h.live(); err != nil {
		return 0, err
	}
	if off >= int64(len(h.n.vol)) {
		return 0, io.EOF
	}
	n := copy(p, h.n.vol[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (h *file) WriteAt(p []byte, off int64) (int, error) {
	h.fs.mu.Lock()
	defer h.fs.mu.Unlock()
	if err := h.live(); err != nil {
		return 0, err
	}
	crash, err := h.fs.tick()
	if err != nil {
		return 0, err
	}
	data := p
	if crash {
		if !h.fs.torn {
			return 0, ErrCrashed
		}
		data = p[:h.fs.rng.Intn(len(p)+1)]
	}
	if end := int(off) + len(data); end > len(h.n.vol) {
		h.n.vol = append(h.n.vol, make([]byte, end-len(h.n.vol))...)
	}
	copy(h.n.vol[off:], data)
	if crash {
		return len(data), ErrCrashed
	}
	return len(p), nil
}

func (h *file) sync() error {
	h.fs.mu.Lock()
	defer h.fs.mu.Unlock()
	if err := h.live(); err != nil {
		return err
	}
	crash, err := h.fs.tick()
	if err != nil {
		return err
	}
	if crash {
		return ErrCrashed
	}
	h.fs.syncs++
	if h.fs.failSync > 0 && h.fs.syncs == h.fs.failSync {
		return ErrInjected
	}
	h.n.dur = append(h.n.dur[:0], h.n.vol...)
	return nil
}

func (h *file) Sync() error     { return h.sync() }
func (h *file) SyncData() error { return h.sync() }

func (h *file) Truncate(size int64) error {
	h.fs.mu.Lock()
	defer h.fs.mu.Unlock()
	if err := h.live(); err != nil {
		return err
	}
	if crash, err := h.fs.tick(); err != nil || crash {
		return ErrCrashed
	}
	if size < int64(len(h.n.vol)) {
		h.n.vol = h.n.vol[:size]
	} else {
		h.n.vol = append(h.n.vol, make([]byte, int(size)-len(h.n.vol))...)
	}
	return nil
}

func (h *file) Preallocate(size int64) error {
	h.fs.mu.Lock()
	defer h.fs.mu.Unlock()
	if err := h.live(); err != nil {
		return err
	}
	if crash, err := h.fs.tick(); err != nil || crash {
		return ErrCrashed
	}
	if size > int64(len(h.n.vol)) {
		h.n.vol = append(h.n.vol, make([]byte, int(size)-len(h.n.vol))...)
	}
	return nil
}

func (h *file) Size() (int64, error) {
	h.fs.mu.Lock()
	defer h.fs.mu.Unlock()
	if err := h.live(); err != nil {
		return 0, err
	}
	return int64(len(h.n.vol)), nil
}

func (h *file) Close() error { return nil }
