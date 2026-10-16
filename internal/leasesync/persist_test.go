// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package leasesync

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStore_FlushIfDirty_NoOpWithoutPersistPath(t *testing.T) {
	s := NewStore()
	s.Upsert(SyncedLease{MAC: "aa:bb", IP: "10.0.0.5", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	if err := s.FlushIfDirty(); err != nil {
		t.Fatalf("FlushIfDirty() with no path set: %v", err)
	}
}

func TestStore_FlushThenLoad_RoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leases.json")
	future := time.Now().Add(time.Hour).Unix()

	s1 := NewStore()
	s1.SetPersistPath(path)
	s1.Upsert(SyncedLease{MAC: "aa:bb", IP: "10.0.0.5", ExpiresAt: future, Hostname: "host1"})
	s1.Upsert(SyncedLease{MAC: "cc:dd", IP: "10.0.0.6", ExpiresAt: future})
	if err := s1.FlushIfDirty(); err != nil {
		t.Fatalf("FlushIfDirty(): %v", err)
	}

	s2 := NewStore()
	s2.SetPersistPath(path)
	n, err := s2.LoadFromDisk()
	if err != nil {
		t.Fatalf("LoadFromDisk(): %v", err)
	}
	if n != 2 {
		t.Fatalf("LoadFromDisk() loaded %d, want 2", n)
	}
	got := s2.Snapshot()
	if len(got) != 2 || got[0].MAC != "aa:bb" || got[0].Hostname != "host1" || got[1].MAC != "cc:dd" {
		t.Fatalf("Snapshot() after load = %v, want the two persisted entries", got)
	}
}

// TestStore_LoadFromDisk_DropsAlreadyExpiredEntry checks an
// already-expired entry is dropped on load.
func TestStore_LoadFromDisk_DropsAlreadyExpiredEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leases.json")
	past := time.Now().Add(-time.Hour).Unix()
	future := time.Now().Add(time.Hour).Unix()

	if err := saveLeasesFile(path, []SyncedLease{
		{MAC: "expired", IP: "10.0.0.9", ExpiresAt: past},
		{MAC: "alive", IP: "10.0.0.10", ExpiresAt: future},
	}); err != nil {
		t.Fatalf("saveLeasesFile(): %v", err)
	}

	s := NewStore()
	s.SetPersistPath(path)
	n, err := s.LoadFromDisk()
	if err != nil {
		t.Fatalf("LoadFromDisk(): %v", err)
	}
	if n != 1 {
		t.Fatalf("LoadFromDisk() loaded %d, want 1 (expired entry must be dropped)", n)
	}
	got := s.Snapshot()
	if len(got) != 1 || got[0].MAC != "alive" {
		t.Fatalf("Snapshot() after load = %v, want only the still-valid entry", got)
	}
}

func TestLoadLeasesFile_MissingFileReturnsNilNoError(t *testing.T) {
	leases, err := loadLeasesFile(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatalf("loadLeasesFile() on missing file: %v", err)
	}
	if leases != nil {
		t.Fatalf("loadLeasesFile() on missing file = %v, want nil", leases)
	}
}

func TestStore_FlushIfDirty_CleanAfterFlushIsNoOp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "leases.json")
	s := NewStore()
	s.SetPersistPath(path)
	s.Upsert(SyncedLease{MAC: "aa:bb", IP: "10.0.0.5", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	if err := s.FlushIfDirty(); err != nil {
		t.Fatalf("first FlushIfDirty(): %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := s.FlushIfDirty(); err != nil {
		t.Fatalf("second FlushIfDirty(): %v", err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatalf("FlushIfDirty() re-wrote the file with nothing dirty")
	}
}
