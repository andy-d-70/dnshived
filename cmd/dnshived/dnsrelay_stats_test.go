// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadDNSRelayStats_MissingFileIsUnavailableNotError(t *testing.T) {
	got := readDNSRelayStats(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if got.Available {
		t.Error("Available = true for a file that was never written, want false")
	}
}

func TestReadDNSRelayStats_MalformedFileIsUnavailableNotError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.json")
	if err := os.WriteFile(path, []byte("not json"), 0644); err != nil {
		t.Fatalf("seed malformed file: %v", err)
	}
	got := readDNSRelayStats(path)
	if got.Available {
		t.Error("Available = true for a malformed file, want false")
	}
}

func TestReadDNSRelayStats_RealSnapshotPassesThrough(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.json")
	content := `{
		"entries": 42, "cache_size": 5000, "cache_max_bytes": 8388608,
		"bytes_used": 12345, "hits": 900, "misses": 100,
		"hit_rate_pct": 90.0, "updated_at": "2026-09-12T12:00:00Z"
	}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("seed real snapshot: %v", err)
	}
	got := readDNSRelayStats(path)
	if !got.Available {
		t.Fatal("Available = false for a real, well-formed snapshot, want true")
	}
	if got.Entries != 42 || got.CacheSize != 5000 || got.CacheMaxBytes != 8388608 {
		t.Errorf("Entries/CacheSize/CacheMaxBytes = %d/%d/%d, want 42/5000/8388608", got.Entries, got.CacheSize, got.CacheMaxBytes)
	}
	if got.Hits != 900 || got.Misses != 100 || got.HitRatePct != 90.0 {
		t.Errorf("Hits/Misses/HitRatePct = %d/%d/%v, want 900/100/90.0", got.Hits, got.Misses, got.HitRatePct)
	}
	if got.UpdatedAt != "2026-09-12T12:00:00Z" {
		t.Errorf("UpdatedAt = %q, want the real value passed through unchanged", got.UpdatedAt)
	}
}
