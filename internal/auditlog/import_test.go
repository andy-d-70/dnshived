// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package auditlog

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func openDisk(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := Open(dir, Options{Key: testKey})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestImportFiles_TakesEveryOldLineOnceAndNeverChangesTheFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	l := New(path)
	l.maxBytes = 300
	for i := 0; i < 30; i++ {
		if err := l.Append("ann", "core-1", "config.save", "old entry "+strings.Repeat("x", i)); err != nil {
			t.Fatal(err)
		}
	}
	old, err := l.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	archives, _ := filepath.Glob(path + ".archive-*")
	if len(archives) == 0 {
		t.Fatal("rotation past .1 archives the previous file instead of deleting it")
	}
	if got := strings.Count(string(old), "\n"); got != 30 {
		t.Fatalf("every line is still on disk after rotations: %d of 30", got)
	}
	files, _ := l.Files()
	before := map[string][]byte{}
	for _, f := range files {
		before[f], _ = os.ReadFile(f)
	}

	s := openDisk(t, filepath.Join(dir, "auditstore"))
	added, skipped, err := ImportFiles(l, s, filepath.Join(dir, "auditstore"))
	if err != nil || added != 30 || skipped != 0 {
		t.Fatalf("import: %d added, %d skipped, %v", added, skipped, err)
	}
	if added, _, err := ImportFiles(l, s, filepath.Join(dir, "auditstore")); err != nil || added != 0 {
		t.Fatalf("a second import adds nothing: %d %v", added, err)
	}
	for f, b := range before {
		if now, _ := os.ReadFile(f); !bytes.Equal(now, b) {
			t.Fatalf("import must not change %s", f)
		}
	}
	var out bytes.Buffer
	if err := s.Export(&out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), old) {
		t.Fatalf("the store's export equals the old files in time order:\n%s\nvs\n%s", out.Bytes(), old)
	}
}

func TestLogger_WithAStoreKeepsEntryAndFileCopyWithTheSameID(t *testing.T) {
	dir := t.TempDir()
	l := New(filepath.Join(dir, "audit.log"))
	s := openDisk(t, filepath.Join(dir, "auditstore"))
	var pushed []StoredEntry
	l.Attach(s, func(e StoredEntry) { pushed = append(pushed, e) })
	if err := l.Append("ann", "core-1", "config.save", "with a store"); err != nil {
		t.Fatal(err)
	}
	if s.Len() != 1 || len(pushed) != 1 {
		t.Fatalf("stored and handed on once: %d %d", s.Len(), len(pushed))
	}
	if added, _, err := ImportFiles(l, s, filepath.Join(dir, "auditstore")); err != nil || added != 0 {
		t.Fatalf("the file copy carries the same id, so importing it adds nothing: %d %v", added, err)
	}

	if err := os.Remove(filepath.Join(dir, "audit.log")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "audit.log"), 0o700); err != nil {
		t.Fatal(err)
	}
	err := l.Append("ann", "core-1", "config.save", "file copy fails")
	if !errors.Is(err, ErrFileCopy) || s.Len() != 2 {
		t.Fatalf("a failing file copy still keeps the entry and says so: %v, %d stored", err, s.Len())
	}
}
