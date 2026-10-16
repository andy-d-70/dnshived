// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package auditlog

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppendAndReadAll(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l := New(path)

	if err := l.Append("op", "worker-a-node", "config.scopes.save", "added scope office"); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := l.Append("op", "worker-a-node", "config.scopes.save", "deleted scope lab"); err != nil {
		t.Fatalf("Append: %v", err)
	}

	data, err := l.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2: %q", len(lines), data)
	}
	var e Entry
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil {
		t.Fatalf("unmarshal first entry: %v", err)
	}
	if e.Actor != "op" || e.Action != "config.scopes.save" || e.Summary != "added scope office" {
		t.Errorf("first entry = %+v, want actor=op action=config.scopes.save summary=%q", e, "added scope office")
	}
}

func TestReadAllNoFileYet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l := New(path)
	data, err := l.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll on nonexistent file: %v", err)
	}
	if data != nil {
		t.Errorf("data = %q, want nil before any Append", data)
	}
}

func TestRotationAtThreshold(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l := New(path)
	l.maxBytes = 100 // small threshold to force rotation quickly in a test

	// Write enough entries to cross the threshold at least once.
	for i := 0; i < 10; i++ {
		if err := l.Append("op", "worker-a-node", "config.scopes.save", "entry padding to grow the file"); err != nil {
			t.Fatalf("Append #%d: %v", i, err)
		}
	}

	backup := path + ".1"
	if _, err := os.Stat(backup); err != nil {
		t.Fatalf("expected a rotated backup file at %s, got: %v", backup, err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat current log: %v", err)
	}
	if info.Size() >= 100+200 { // generous slack — just confirming it didn't grow unbounded
		t.Errorf("current log size = %d, rotation doesn't seem to have kept it bounded", info.Size())
	}
}

func TestReadAll_IncludesRotatedBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l := New(path)
	l.maxBytes = 100

	for i := 0; i < 10; i++ {
		if err := l.Append("op", "worker-a-node", "config.scopes.save", "first-generation padding entry"); err != nil {
			t.Fatalf("Append #%d: %v", i, err)
		}
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("expected a rotated backup to exist: %v", err)
	}

	if err := l.Append("op", "worker-a-node", "config.scopes.save", "second-generation entry"); err != nil {
		t.Fatalf("Append after rotation: %v", err)
	}

	data, err := l.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !strings.Contains(string(data), "first-generation padding entry") {
		t.Error("ReadAll must include the rotated-out backup's entries, not just the current file")
	}
	if !strings.Contains(string(data), "second-generation entry") {
		t.Error("ReadAll must include the current file's entries")
	}

	// Backup content must come before current-file content — chronological
	// order, oldest first.
	backupIdx := strings.Index(string(data), "first-generation")
	currentIdx := strings.Index(string(data), "second-generation")
	if backupIdx < 0 || currentIdx < 0 || backupIdx > currentIdx {
		t.Errorf("expected backup entries before current entries, got backupIdx=%d currentIdx=%d", backupIdx, currentIdx)
	}
}

// TestReadAll_NoBackupYet confirms ReadAll behaves exactly as before when
// no rotation has ever happened — no spurious error from a missing .1.
func TestReadAll_NoBackupYet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l := New(path)
	if err := l.Append("op", "worker-a-node", "config.scopes.save", "only entry"); err != nil {
		t.Fatalf("Append: %v", err)
	}
	data, err := l.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !strings.Contains(string(data), "only entry") {
		t.Errorf("missing expected entry: %q", data)
	}
}

func TestAppendEntriesAreValidJSONLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l := New(path)
	if err := l.Append("admin", "worker-b-node", "config.scopes.delete", "removed scope test"); err != nil {
		t.Fatalf("Append: %v", err)
	}
	data, _ := l.ReadAll()
	if !bytes.HasSuffix(data, []byte("\n")) {
		t.Error("entries should be newline-terminated for line-oriented reading")
	}
}
