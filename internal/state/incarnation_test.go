// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestNextIncarnation_CorruptFileMovesAboveAnyCount(t *testing.T) {
	for name, content := range map[string]string{"garbage": "not-a-number", "empty": ""} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "incarnation"), []byte(content), 0o640); err != nil {
				t.Fatalf("write corrupt fixture: %v", err)
			}
			before := uint64(time.Now().Unix())
			got, err := NextIncarnation(dir)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got < before {
				t.Errorf("got %d, want >= %d: a corrupt file must not restart the count", got, before)
			}
			again, err := NextIncarnation(dir)
			if err != nil || again != got+1 {
				t.Errorf("next start = %d, %v; want %d", again, err, got+1)
			}
		})
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
