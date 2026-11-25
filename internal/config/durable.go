// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

const (
	intentFileName = "save.intent"
	lockFileName   = ".lock"
	newSuffix      = ".new"
)

// splitStep lets tests stop a split save after a given number of steps, the way a crash would.
var splitStep func(step string) error

func step(name string) error {
	if splitStep != nil {
		return splitStep(name)
	}
	return nil
}

func syncDir(dir string) error {
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

// writeDurable writes data to path through a synced temporary file and a rename, then syncs the directory, so a
// confirmed write survives a power cut and a crash never leaves a partial file.
func writeDurable(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(tmp)
		return werr
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(dir)
}

// saveIntent is the commit point of a split save: once it is on disk the save completes, after a crash too.
type saveIntent struct {
	Manifest json.RawMessage `json:"manifest"`
	Parts    []string        `json:"parts"`
	Remove   []string        `json:"remove,omitempty"`
}

type dirLock struct{ f *os.File }

// lockDir takes the save lock of a split directory; wait false gives up at once when another process holds it.
func lockDir(dir string, wait bool) (*dirLock, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, lockFileName), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	how := syscall.LOCK_EX
	if !wait {
		how |= syscall.LOCK_NB
	}
	if err := syscall.Flock(int(f.Fd()), how); err != nil {
		f.Close()
		return nil, err
	}
	return &dirLock{f: f}, nil
}

func (l *dirLock) release() {
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	l.f.Close()
}

func readIntent(dir string) (*saveIntent, error) {
	raw, err := readCapped(filepath.Join(dir, intentFileName), maxManifestBytes)
	if err != nil {
		return nil, err
	}
	var in saveIntent
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, fmt.Errorf("parse %s: %w", intentFileName, err)
	}
	for _, p := range append(append([]string{}, in.Parts...), in.Remove...) {
		if !safeRel(p) {
			return nil, fmt.Errorf("%s names an unsafe path %q", intentFileName, p)
		}
	}
	return &in, nil
}

func safeRel(p string) bool {
	return p != "" && filepath.IsLocal(filepath.FromSlash(p)) && !strings.Contains(p, "..")
}

func partDirs(dir string, rels []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range rels {
		d := filepath.Dir(filepath.Join(dir, filepath.FromSlash(r)))
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}

// finishSplit completes a save from its intent: new parts into place, the manifest, stale parts away, the intent
// last. Every step can be repeated, so a crash during it only means it runs again.
func finishSplit(dir string, in *saveIntent) error {
	for _, p := range in.Parts {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.Rename(full+newSuffix, full); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("move part %s into place: %w", p, err)
		}
		if err := step("rename " + p); err != nil {
			return err
		}
	}
	for _, d := range partDirs(dir, in.Parts) {
		if err := syncDir(d); err != nil {
			return err
		}
	}
	if err := writeDurable(filepath.Join(dir, manifestFileName), in.Manifest, 0o600); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	if err := step("manifest"); err != nil {
		return err
	}
	for _, p := range in.Remove {
		if err := os.Remove(filepath.Join(dir, filepath.FromSlash(p))); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove stale part %s: %w", p, err)
		}
	}
	for _, d := range partDirs(dir, in.Remove) {
		if err := syncDir(d); err != nil {
			return err
		}
	}
	if err := os.Remove(filepath.Join(dir, intentFileName)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return syncDir(dir)
}

// recoverSplit finishes a save that a crash interrupted after its intent was written, or throws away the new
// parts of one interrupted before. It does nothing while another process holds the save lock.
func recoverSplit(dir string) error {
	l, err := lockDir(dir, false)
	if err != nil {
		return err
	}
	defer l.release()
	in, err := readIntent(dir)
	if err == nil {
		return finishSplit(dir, in)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return removeStray(dir)
}

// removeStray deletes new parts that no intent refers to: a save that stopped before its commit point left them.
// Call it only while holding the save lock.
func removeStray(dir string) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil || d.IsDir() || !strings.HasSuffix(p, newSuffix) {
			return werr
		}
		return os.Remove(p)
	})
}
