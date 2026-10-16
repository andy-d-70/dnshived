// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package reliability

import (
	"path/filepath"
	"sync"
	"testing"
)

func TestNext_NeverObservedHealthyStaysFull(t *testing.T) {
	got := Next(Entry{}, false, true)
	if got.Score != 100 {
		t.Errorf("Next() score = %d, want 100", got.Score)
	}
	if !got.WasHealthy {
		t.Error("WasHealthy = false, want true")
	}
}

func TestNext_NeverObservedUnhealthyDecaysOnce(t *testing.T) {
	got := Next(Entry{}, false, false)
	want := int(100 * DecayFactor)
	if got.Score != want {
		t.Errorf("Next() score = %d, want %d", got.Score, want)
	}
	if got.WasHealthy {
		t.Error("WasHealthy = true, want false")
	}
}

func TestNext_ConfirmedDownTransitionDecays(t *testing.T) {
	prev := Entry{Score: 100, WasHealthy: true}
	got := Next(prev, true, false)
	want := int(100 * DecayFactor)
	if got.Score != want {
		t.Errorf("Next() score = %d, want %d", got.Score, want)
	}
}

func TestNext_SustainedDownDoesNotKeepDecaying(t *testing.T) {
	prev := Entry{Score: 70, WasHealthy: false}
	got := Next(prev, true, false)
	if got.Score != 70 {
		t.Errorf("Next() score = %d, want 70 unchanged", got.Score)
	}
}

func TestNext_RecoveryAccruesEveryUpTickCappedAt100(t *testing.T) {
	got := Next(Entry{Score: 70, WasHealthy: false}, true, true)
	if got.Score != 70+RecoveryStep {
		t.Errorf("Next() score = %d, want %d", got.Score, 70+RecoveryStep)
	}
	got = Next(Entry{Score: 99, WasHealthy: true}, true, true)
	if got.Score != 100 {
		t.Errorf("Next() score = %d, want 100 (capped, not 102)", got.Score)
	}
}

func TestNext_NeverNegative(t *testing.T) {
	got := Next(Entry{Score: 1, WasHealthy: true}, true, false)
	if got.Score < 0 {
		t.Errorf("Next() score = %d, want >= 0", got.Score)
	}
}

func TestStore_InMemoryOnly_NoDiskIO(t *testing.T) {
	s := NewStore("")
	if got := s.Observe("ens19", true); got != 100 {
		t.Errorf("Observe() = %d, want 100", got)
	}
	e, ok := s.Get("ens19")
	if !ok || e.Score != 100 {
		t.Errorf("Get() = %+v, %v, want Score=100, true", e, ok)
	}
}

func TestStore_ObserveDownThenUp_MatchesNextDirectly(t *testing.T) {
	s := NewStore("")
	if got := s.Observe("ens19", false); got != int(100*DecayFactor) {
		t.Errorf("first Observe(false) = %d, want %d", got, int(100*DecayFactor))
	}
	if got := s.Observe("ens19", false); got != int(100*DecayFactor) {
		t.Errorf("second Observe(false) = %d, want unchanged %d (no repeat decay)", got, int(100*DecayFactor))
	}
	want := int(100*DecayFactor) + RecoveryStep
	if got := s.Observe("ens19", true); got != want {
		t.Errorf("Observe(true) after down = %d, want %d", got, want)
	}
}

func TestStore_PersistsAcrossReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reliability.json")

	s1 := NewStore(path)
	s1.Observe("ens19", false)
	s1.Observe("ens20", true)

	s2 := NewStore(path)
	e19, ok := s2.Get("ens19")
	if !ok || e19.Score != int(100*DecayFactor) {
		t.Errorf("reloaded ens19 = %+v, %v, want Score=%d", e19, ok, int(100*DecayFactor))
	}
	e20, ok := s2.Get("ens20")
	if !ok || e20.Score != 100 {
		t.Errorf("reloaded ens20 = %+v, %v, want Score=100", e20, ok)
	}
	if got := s2.Observe("ens19", false); got != int(100*DecayFactor) {
		t.Errorf("Observe(false) after reload = %d, want %d unchanged (history preserved)", got, int(100*DecayFactor))
	}
}

func TestNewStore_MissingFileStartsEmpty(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(filepath.Join(dir, "does-not-exist.json"))
	if _, ok := s.Get("ens19"); ok {
		t.Error("Get() on a fresh store backed by a missing file = found an entry, want none")
	}
}

func TestNewStore_CorruptFileStartsEmptyNotError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reliability.json")
	if err := atomicWriteFile(path, []byte("not valid json"), 0o640); err != nil {
		t.Fatalf("setup: %v", err)
	}
	s := NewStore(path)
	if _, ok := s.Get("ens19"); ok {
		t.Error("Get() on a store backed by a corrupt file = found an entry, want none")
	}
	// Must still be usable afterward.
	if got := s.Observe("ens19", true); got != 100 {
		t.Errorf("Observe() after corrupt-file recovery = %d, want 100", got)
	}
}

func TestStore_Reset_ClearsEntryBackToNeverObserved(t *testing.T) {
	s := NewStore("")
	s.Observe("ens19", false)
	s.Observe("ens19", false)
	if e, _ := s.Get("ens19"); e.Score == 100 {
		t.Fatalf("setup failed: expected a decayed score before Reset")
	}

	s.Reset("ens19")
	if _, ok := s.Get("ens19"); ok {
		t.Error("Get() after Reset() found an entry, want none (never-observed)")
	}
	// The very next Observe must start fresh from 100, not resume the
	// old decayed history.
	if got := s.Observe("ens19", true); got != 100 {
		t.Errorf("Observe(true) right after Reset() = %d, want 100 (fresh start)", got)
	}
}

func TestStore_Reset_PersistsAcrossReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reliability.json")

	s1 := NewStore(path)
	s1.Observe("ens19", false)
	s1.Reset("ens19")

	s2 := NewStore(path)
	if _, ok := s2.Get("ens19"); ok {
		t.Error("reloaded store still has ens19 after Reset(), want it gone")
	}
}

func TestStore_Snapshot_IsADefensiveCopy(t *testing.T) {
	s := NewStore("")
	s.Observe("ens19", true)
	snap := s.Snapshot()
	snap["ens19"] = Entry{Score: 0}
	if e, _ := s.Get("ens19"); e.Score != 100 {
		t.Errorf("mutating Snapshot()'s result affected the store's own data: Get() = %+v", e)
	}
}

func TestStore_RestoreAll_ReplacesEntireContents(t *testing.T) {
	s := NewStore("")
	s.Observe("stale-trunk", false)
	s.Observe("stale-trunk", false)

	restored := map[string]Entry{
		"ens19": {Score: 73, WasHealthy: true},
	}
	s.RestoreAll(restored)

	if _, ok := s.Get("stale-trunk"); ok {
		t.Error("RestoreAll() left the pre-existing entry in place, want a full replace")
	}
	if e, ok := s.Get("ens19"); !ok || e.Score != 73 {
		t.Errorf("Get(\"ens19\") after RestoreAll() = %+v, ok=%v, want Score=73", e, ok)
	}
}

func TestStore_RestoreAll_IsADefensiveCopyOfTheInput(t *testing.T) {
	s := NewStore("")
	entries := map[string]Entry{"ens19": {Score: 50}}
	s.RestoreAll(entries)
	entries["ens19"] = Entry{Score: 0}
	if e, _ := s.Get("ens19"); e.Score != 50 {
		t.Errorf("mutating the caller's own map after RestoreAll() affected the store: Get() = %+v", e)
	}
}

func TestStore_RestoreAll_PersistsAcrossReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reliability.json")

	s1 := NewStore(path)
	s1.RestoreAll(map[string]Entry{"ens19": {Score: 42}})

	s2 := NewStore(path)
	if e, ok := s2.Get("ens19"); !ok || e.Score != 42 {
		t.Errorf("reloaded store after RestoreAll() = %+v, ok=%v, want Score=42", e, ok)
	}
}

func TestStore_ConcurrentObserve_NeverRacesTheSharedTempFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reliability.json")
	s := NewStore(path)

	const goroutines = 20
	const observesEach = 10
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < observesEach; i++ {
				s.Observe("ens19", i%2 == 0)
			}
		}(g)
	}
	wg.Wait()

	reloaded := NewStore(path)
	if _, ok := reloaded.Get("ens19"); !ok {
		t.Error("reloaded store after concurrent Observe() calls has no entry for ens19 — the persisted file was lost or corrupted by a write race")
	}
}
