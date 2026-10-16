// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package topobeacon

import (
	"context"
	"sort"
	"sync"
	"testing"
	"time"
)

// fakeStarts records which interfaces currently have a running
// sender/listener, without opening sockets or touching interfaces.
type fakeStarts struct {
	mu     sync.Mutex
	active map[string]int
	starts int
}

func (f *fakeStarts) start(ctx context.Context, role string, spec IfaceSpec, store *Store, interval time.Duration) {
	f.mu.Lock()
	f.active[spec.Name]++
	f.starts++
	f.mu.Unlock()
	<-ctx.Done()
	f.mu.Lock()
	f.active[spec.Name]--
	if f.active[spec.Name] == 0 {
		delete(f.active, spec.Name)
	}
	f.mu.Unlock()
}

func (f *fakeStarts) snapshot() ([]string, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var names []string
	for n := range f.active {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, f.starts
}

func waitFor(t *testing.T, f *fakeStarts, want []string) int {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		got, starts := f.snapshot()
		if equalStrings(got, want) {
			return starts
		}
		if time.Now().After(deadline) {
			t.Fatalf("active interfaces = %v, want %v", got, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func newTestRunner(f *fakeStarts) (*Runner, *Store) {
	store := NewStore(time.Second, "core-1")
	r := NewRunner("core-1", store, time.Second)
	r.start = f.start
	return r, store
}

func TestRunner_StartsOnlyTheDifference(t *testing.T) {
	f := &fakeStarts{active: map[string]int{}}
	r, _ := newTestRunner(f)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgmt := IfaceSpec{Name: "ens18", Kind: KindMgmt}
	ens19 := IfaceSpec{Name: "ens19", Kind: KindTrunk}
	ens20 := IfaceSpec{Name: "ens20", Kind: KindTrunk}

	added, removed := r.Update(ctx, []IfaceSpec{mgmt})
	if len(added) != 1 || len(removed) != 0 {
		t.Fatalf("first update: added %v removed %v", added, removed)
	}
	if starts := waitFor(t, f, []string{"ens18"}); starts != 1 {
		t.Fatalf("starts = %d, want 1", starts)
	}

	// A scope on ens19 was hot-reloaded in: only ens19 starts, mgmt is untouched.
	added, removed = r.Update(ctx, []IfaceSpec{mgmt, ens19})
	if len(added) != 1 || added[0] != ens19 || len(removed) != 0 {
		t.Fatalf("hot reload: added %v removed %v", added, removed)
	}
	if starts := waitFor(t, f, []string{"ens18", "ens19"}); starts != 2 {
		t.Fatalf("starts = %d, want 2 (mgmt must not be restarted)", starts)
	}

	// Same set again: nothing changes.
	if added, removed = r.Update(ctx, []IfaceSpec{ens19, mgmt}); len(added)+len(removed) != 0 {
		t.Fatalf("unchanged update: added %v removed %v", added, removed)
	}

	// ens19's last scope moved to ens20.
	added, removed = r.Update(ctx, []IfaceSpec{mgmt, ens20})
	if len(added) != 1 || added[0] != ens20 || len(removed) != 1 || removed[0] != ens19 {
		t.Fatalf("move: added %v removed %v", added, removed)
	}
	waitFor(t, f, []string{"ens18", "ens20"})
}

func TestRunner_RemovedInterfaceSightingsAreForgotten(t *testing.T) {
	f := &fakeStarts{active: map[string]int{}}
	r, store := newTestRunner(f)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ens19 := IfaceSpec{Name: "ens19", Kind: KindTrunk}
	ens20 := IfaceSpec{Name: "ens20", Kind: KindTrunk}
	r.Update(ctx, []IfaceSpec{ens19, ens20})
	store.record("ens19", KindTrunk, Beacon{Magic: Magic, Role: "core-2", Iface: "ens19", Kind: KindTrunk})
	store.record("ens20", KindTrunk, Beacon{Magic: Magic, Role: "core-2", Iface: "ens20", Kind: KindTrunk})

	r.Update(ctx, []IfaceSpec{ens20})
	for _, s := range store.Snapshot() {
		if s.MyIface == "ens19" {
			t.Errorf("sighting on removed ens19 still present: %+v", s)
		}
	}
	if len(store.Snapshot()) != 1 {
		t.Errorf("ens20's sighting should survive, got %+v", store.Snapshot())
	}
}
