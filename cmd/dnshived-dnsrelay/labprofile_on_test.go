// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

//go:build labprofile

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func labWrite(t *testing.T, dir, name, body string, perm os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, perm); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGate(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name    string
		body    string
		perm    os.FileMode
		want    int
		wantErr bool
	}{
		{"default seconds", "", 0o644, labDefaultSeconds, false},
		{"explicit seconds", "45\n", 0o644, 45, false},
		{"clamped low", "1", 0o644, labMinSeconds, false},
		{"clamped high", "9999", 0o644, labMaxSeconds, false},
		{"junk keeps the default", "abc", 0o644, labDefaultSeconds, false},
		{"only the first word counts", "20 and more text", 0o600, 20, false},
		{"group writable", "30", 0o664, 0, true},
		{"world writable", "30", 0o666, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := labWrite(t, dir, "enable", tt.body, tt.perm)
			got, err := labGate(p, false)
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Errorf("labGate() = %d, %v; want %d, err=%v", got, err, tt.want, tt.wantErr)
			}
		})
	}
	if _, err := labGate(filepath.Join(dir, "missing"), false); err == nil {
		t.Error("a missing enable file must keep profiling off")
	}
	target := labWrite(t, dir, "real", "30", 0o644)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := labGate(link, false); err == nil {
		t.Error("a symlink must be refused")
	}
	if _, err := labGate(dir, false); err == nil {
		t.Error("a directory must be refused")
	}
	if os.Getuid() != 0 {
		if _, err := labGate(target, true); err == nil {
			t.Error("a file not owned by root must be refused when root ownership is required")
		}
	}
}

func TestCaptureWritesPrivateFilesAndPrunes(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "lab-profile")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	for i := 0; i < 20; i++ {
		p := labWrite(t, dir, "old-"+string(rune('a'+i)), "x", 0o600)
		os.Chtimes(p, old.Add(time.Duration(i)*time.Minute), old.Add(time.Duration(i)*time.Minute))
	}
	<-labCapture(base, 1)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != labKeepFiles {
		t.Errorf("kept %d files, want %d", len(entries), labKeepFiles)
	}
	var cpu, heap, goroutine int
	for _, e := range entries {
		info, _ := e.Info()
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s has mode %v, want 0600", e.Name(), info.Mode().Perm())
		}
		switch {
		case len(e.Name()) > 4 && e.Name()[:4] == "cpu-":
			cpu++
		case len(e.Name()) > 5 && e.Name()[:5] == "heap-":
			heap++
		case len(e.Name()) > 10 && e.Name()[:10] == "goroutine-":
			goroutine++
		}
	}
	if cpu != 1 || heap != 1 || goroutine != 1 {
		t.Errorf("want one cpu, heap and goroutine file, got %d %d %d", cpu, heap, goroutine)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Errorf("directory mode %v, want 0700", fi.Mode().Perm())
	}
}

func TestCaptureRefusesASecondRunAtTheSameTime(t *testing.T) {
	base := t.TempDir()
	first := labCapture(base, 2)
	select {
	case <-labCapture(base, 1):
	case <-time.After(time.Second):
		t.Fatal("a second labCapture while one runs must return at once")
	}
	<-first
}

func TestMarkerAndSuffixAreSet(t *testing.T) {
	if !labEnabled || labMarker == "" || labVersionSuffix() == "" {
		t.Error("the lab build must identify itself")
	}
}
