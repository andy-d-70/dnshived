// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package leasesync

import (
	"testing"
	"time"
)

func TestStore_UpsertThenSnapshot(t *testing.T) {
	s := NewStore()
	s.Upsert(SyncedLease{MAC: "aa:bb", IP: "10.0.0.5", ExpiresAt: 1000})
	got := s.Snapshot()
	if len(got) != 1 || got[0].IP != "10.0.0.5" {
		t.Fatalf("Snapshot() = %v, want one entry with IP 10.0.0.5", got)
	}
}

func TestStore_UpsertSameMACTwice_OverwritesNotDuplicates(t *testing.T) {
	s := NewStore()
	s.Upsert(SyncedLease{MAC: "aa:bb", IP: "10.0.0.5", ExpiresAt: 1000})
	s.Upsert(SyncedLease{MAC: "aa:bb", IP: "10.0.0.5", ExpiresAt: 2000}) // renewal: same IP, extended TTL
	got := s.Snapshot()
	if len(got) != 1 {
		t.Fatalf("Snapshot() = %v, want exactly one entry after two upserts of the same MAC", got)
	}
	if got[0].ExpiresAt != 2000 {
		t.Errorf("ExpiresAt = %d, want the later value 2000 (renewal must win)", got[0].ExpiresAt)
	}
}

// TestStore_UpsertSameMACDifferentIP_ReplacesOldEntry covers a client
// releasing and picking up a different address.
func TestStore_UpsertSameMACDifferentIP_ReplacesOldEntry(t *testing.T) {
	s := NewStore()
	s.Upsert(SyncedLease{MAC: "aa:bb", IP: "10.0.0.5", ExpiresAt: 1000})
	s.Upsert(SyncedLease{MAC: "aa:bb", IP: "10.0.0.9", ExpiresAt: 1000})
	got := s.Snapshot()
	if len(got) != 1 || got[0].IP != "10.0.0.9" {
		t.Fatalf("Snapshot() = %v, want exactly one entry with the new IP 10.0.0.9", got)
	}
}

func TestStore_Remove(t *testing.T) {
	s := NewStore()
	s.Upsert(SyncedLease{MAC: "aa:bb", IP: "10.0.0.5", ExpiresAt: 1000})
	s.Remove("aa:bb")
	if got := s.Snapshot(); len(got) != 0 {
		t.Errorf("Snapshot() = %v, want empty after Remove", got)
	}
}

// TestStore_Remove_UnknownMACIsHarmless covers a "del" arriving for an
// entry this side never saw (or already pruned) — must not panic or
// error.
func TestStore_Remove_UnknownMACIsHarmless(t *testing.T) {
	s := NewStore()
	s.Remove("never-seen")
	if got := s.Snapshot(); len(got) != 0 {
		t.Errorf("Snapshot() = %v, want empty", got)
	}
}

// TestStore_PruneExpired_RemovesOnlyPastEntries checks only expired
// entries are pruned, so none block the pool.
func TestStore_PruneExpired_RemovesOnlyPastEntries(t *testing.T) {
	s := NewStore()
	now := time.Unix(10_000, 0)
	s.Upsert(SyncedLease{MAC: "expired", IP: "10.0.0.1", ExpiresAt: 9_999}) // already past
	s.Upsert(SyncedLease{MAC: "exact", IP: "10.0.0.2", ExpiresAt: 10_000})  // exactly now — must go too
	s.Upsert(SyncedLease{MAC: "future", IP: "10.0.0.3", ExpiresAt: 10_001}) // must survive

	n := s.PruneExpired(now)
	if n != 2 {
		t.Errorf("PruneExpired() removed %d, want 2 (expired + exact)", n)
	}
	got := s.Snapshot()
	if len(got) != 1 || got[0].MAC != "future" {
		t.Fatalf("Snapshot() after prune = %v, want only \"future\" to survive", got)
	}
}

func TestStore_Len(t *testing.T) {
	s := NewStore()
	if s.Len() != 0 {
		t.Errorf("Len() = %d on empty store, want 0", s.Len())
	}
	s.Upsert(SyncedLease{MAC: "aa:bb", IP: "10.0.0.5", ExpiresAt: 1000})
	if s.Len() != 1 {
		t.Errorf("Len() = %d, want 1", s.Len())
	}
}
