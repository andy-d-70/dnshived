// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

// Package vfs is the narrow filesystem surface the DNS store needs, so tests can inject faults.
package vfs

import (
	"errors"
	"io"
	"os"
	"sort"
	"syscall"
)

type File interface {
	io.ReaderAt
	io.WriterAt
	Sync() error
	SyncData() error
	Truncate(size int64) error
	Preallocate(size int64) error
	Size() (int64, error)
	Close() error
}

type FS interface {
	OpenFile(name string, flag int, perm os.FileMode) (File, error)
	Rename(oldpath, newpath string) error
	Remove(name string) error
	ReadDir(dir string) ([]string, error)
	MkdirAll(dir string, perm os.FileMode) error
	SyncDir(dir string) error
	Lock(name string) (io.Closer, error)
	Mode(name string) (os.FileMode, error)
}

type OS struct{}

type osFile struct{ f *os.File }

func (o OS) OpenFile(name string, flag int, perm os.FileMode) (File, error) {
	f, err := os.OpenFile(name, flag|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, perm)
	if err != nil {
		return nil, err
	}
	return &osFile{f: f}, nil
}

func (OS) Rename(oldpath, newpath string) error { return os.Rename(oldpath, newpath) }

func (OS) Remove(name string) error { return os.Remove(name) }

func (OS) ReadDir(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, nil
}

func (OS) MkdirAll(dir string, perm os.FileMode) error { return os.MkdirAll(dir, perm) }

func (OS) SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

func (OS) Mode(name string) (os.FileMode, error) {
	st, err := os.Lstat(name)
	if err != nil {
		return 0, err
	}
	return st.Mode(), nil
}

type lockFile struct{ f *os.File }

func (l *lockFile) Close() error {
	err := syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	if cerr := l.f.Close(); err == nil {
		err = cerr
	}
	return err
}

var ErrLocked = errors.New("vfs: lock held by another process")

func (OS) Lock(name string) (io.Closer, error) {
	f, err := os.OpenFile(name, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, err
	}
	return &lockFile{f: f}, nil
}

func (o *osFile) ReadAt(p []byte, off int64) (int, error)  { return o.f.ReadAt(p, off) }
func (o *osFile) WriteAt(p []byte, off int64) (int, error) { return o.f.WriteAt(p, off) }
func (o *osFile) Sync() error                              { return o.f.Sync() }
func (o *osFile) SyncData() error                          { return syscall.Fdatasync(int(o.f.Fd())) }
func (o *osFile) Truncate(size int64) error                { return o.f.Truncate(size) }
func (o *osFile) Close() error                             { return o.f.Close() }

func (o *osFile) Preallocate(size int64) error {
	if err := syscall.Fallocate(int(o.f.Fd()), 0, 0, size); err != nil {
		if errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.ENOSYS) {
			return o.f.Truncate(size)
		}
		return err
	}
	return nil
}

func (o *osFile) Size() (int64, error) {
	st, err := o.f.Stat()
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}
