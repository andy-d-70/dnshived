// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNextIncarnation_StartsAtOne(t *testing.T) {
	dir := t.TempDir()
	got, err := NextIncarnation(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 1 {
		t.Errorf("got %d, want 1", got)
	}
}

func TestNextIncarnation_IncreasesAcrossCalls(t *testing.T) {
	dir := t.TempDir()
	for want := uint64(1); want <= 5; want++ {
		got, err := NextIncarnation(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != want {
			t.Errorf("call %d: got %d, want %d", want, got, want)
		}
	}
}

func TestNextIncarnation_PersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	if _, err := NextIncarnation(dir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := NextIncarnation(dir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Simulate a fresh process re-reading persisted state.
	got, err := NextIncarnation(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 3 {
		t.Errorf("got %d, want 3 (persisted across simulated restart)", got)
	}
}

func TestNextIncarnation_CorruptFileResetsForward(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "incarnation")
	if err := os.WriteFile(path, []byte("not-a-number"), 0o640); err != nil {
		t.Fatalf("write corrupt fixture: %v", err)
	}
	got, err := NextIncarnation(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 1 {
		t.Errorf("got %d, want 1 (corrupt file treated as starting from 0)", got)
	}
}

func TestNextIncarnation_NoTempFileLeftBehind(t *testing.T) {
	dir := t.TempDir()
	if _, err := NextIncarnation(dir); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "incarnation.tmp")); !os.IsNotExist(err) {
		t.Errorf("expected no leftover .tmp file, stat err: %v", err)
	}
}

func TestNextIncarnation_CreatesDirIfMissing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "state")
	got, err := NextIncarnation(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 1 {
		t.Errorf("got %d, want 1", got)
	}
}
