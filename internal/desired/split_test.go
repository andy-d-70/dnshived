// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package desired

import (
	"reflect"
	"testing"
	"time"
)

func TestMapHash_OrderIndependentAndContentSensitive(t *testing.T) {
	a := MapHash(OwnerMap([]Assignment{{"office", "core-1"}, {"dante-", "core-2"}}))
	b := MapHash(OwnerMap([]Assignment{{"dante-", "core-2"}, {"office", "core-1"}}))
	c := MapHash(OwnerMap([]Assignment{{"dante-", "core-2"}, {"office", "core-3"}}))
	if a != b {
		t.Errorf("same contents, different order: %s vs %s", a, b)
	}
	if a == c {
		t.Error("different owner, same hash")
	}
	if MapHash(map[string]string{"ab": "c"}) == MapHash(map[string]string{"a": "bc"}) {
		t.Error("field boundary not part of the hash")
	}
}

func TestDiffOwners_ListsOnlyDisagreements(t *testing.T) {
	here := map[string]string{"office": "core-1", "dante-": "core-2", "lab": ""}
	peer := map[string]string{"office": "core-3", "dante-": "core-2", "new": "core-1"}
	want := []string{
		"lab: here=none peer=missing",
		"new: here=missing peer=core-1",
		"office: here=core-1 peer=core-3",
	}
	if got := DiffOwners(here, peer); !reflect.DeepEqual(got, want) {
		t.Errorf("DiffOwners = %v, want %v", got, want)
	}
}

func TestSplitTracker_DebouncesRepeatsAndResolves(t *testing.T) {
	tr := NewSplitTracker()
	t0 := time.Unix(1_800_000_000, 0)
	if a, _ := tr.Observe(t0, "core-3", true); a != SplitNone {
		t.Fatal("warned on the first observation")
	}
	if a, _ := tr.Observe(t0.Add(40*time.Second), "core-3", true); a != SplitNone {
		t.Fatal("warned within the unserved grace")
	}
	if a, d := tr.Observe(t0.Add(46*time.Second), "core-3", true); a != SplitWarn || d != 46*time.Second {
		t.Fatalf("got %v %v, want a warning after 46s", a, d)
	}
	if a, _ := tr.Observe(t0.Add(2*time.Minute), "core-3", true); a != SplitNone {
		t.Fatal("repeated too early")
	}
	if a, _ := tr.Observe(t0.Add(46*time.Second+splitRepeat), "core-3", true); a != SplitWarn {
		t.Fatal("no repeat")
	}
	if a, d := tr.Observe(t0.Add(10*time.Minute), "core-3", false); a != SplitResolved || d != 10*time.Minute {
		t.Fatalf("got %v %v, want resolved after 10m", a, d)
	}
	if a, _ := tr.Observe(t0.Add(11*time.Minute), "core-3", false); a != SplitNone {
		t.Fatal("resolved twice")
	}
}

func TestSplitTracker_ShortSplitIsSilent(t *testing.T) {
	tr := NewSplitTracker()
	t0 := time.Unix(1_800_000_000, 0)
	tr.Observe(t0, "core-1", true)
	if a, _ := tr.Observe(t0.Add(4*time.Second), "core-1", false); a != SplitNone {
		t.Fatalf("a split shorter than %s must stay silent, got %v", splitLogMin, a)
	}
}

func TestSplitTracker_HealedWithinGraceIsLoggedNotWarned(t *testing.T) {
	tr := NewSplitTracker()
	t0 := time.Unix(1_800_000_000, 0)
	tr.Observe(t0, "core-3", true)
	if a, _ := tr.Observe(t0.Add(25*time.Second), "core-3", true); a != SplitNone {
		t.Fatalf("warned at 25s: %v", a)
	}
	if a, d := tr.Observe(t0.Add(30*time.Second), "core-3", false); a != SplitHealed || d != 30*time.Second {
		t.Fatalf("got %v %v, want healed after 30s", a, d)
	}
}

func TestDisputedScopes(t *testing.T) {
	got := DisputedScopes(map[string]string{"office": "core-1", "dante-": "core-2", "a": "core-1"},
		map[string]string{"office": "core-3", "dante-": "core-2", "b": "core-2"})
	if want := []string{"a", "b", "office"}; !reflect.DeepEqual(got, want) {
		t.Errorf("DisputedScopes = %v, want %v", got, want)
	}
}
