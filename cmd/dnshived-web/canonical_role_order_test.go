// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"reflect"
	"testing"
)

func TestSortNodesByCanonicalRole_OrdersNumerically(t *testing.T) {
	in := []NodeConfig{
		{Name: "core-1", Addr: "a"},
		{Name: "core-3", Addr: "c"},
		{Name: "core-2", Addr: "b"},
	}
	out := sortNodesByCanonicalRole(in)
	got := []string{out[0].Name, out[1].Name, out[2].Name}
	want := []string{"core-1", "core-2", "core-3"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("order = %v, want %v", got, want)
	}
	// Original slice (and its order) must be left untouched.
	if in[0].Name != "core-1" || in[1].Name != "core-3" || in[2].Name != "core-2" {
		t.Errorf("input slice mutated: %v", in)
	}
}

func TestSortNodesByCanonicalRole_ReordersAfterAReplaceAppendedAtTheEnd(t *testing.T) {
	in := []NodeConfig{
		{Name: "core-3"},
		{Name: "core-1"},
		{Name: "core-2"}, // appended back after being missing
	}
	out := sortNodesByCanonicalRole(in)
	for i, want := range []string{"core-1", "core-2", "core-3"} {
		if out[i].Name != want {
			t.Errorf("out[%d].Name = %q, want %q", i, out[i].Name, want)
		}
	}
}

// TestMissingCoreRoles_ReportsAbsentRolesInCanonicalOrder confirms the
// offboard-and-not-yet-replaced hint case.
func TestMissingCoreRoles_ReportsAbsentRolesInCanonicalOrder(t *testing.T) {
	nodes := []NodeConfig{{Name: "core-1"}}
	got := missingCoreRoles(nodes)
	want := []string{"core-2", "core-3"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("missingCoreRoles = %v, want %v", got, want)
	}
}

// TestMissingCoreRoles_EmptyWhenAllThreePresent confirms no false hints
// when the cluster is fully onboarded.
func TestMissingCoreRoles_EmptyWhenAllThreePresent(t *testing.T) {
	nodes := []NodeConfig{{Name: "core-3"}, {Name: "core-1"}, {Name: "core-2"}}
	if got := missingCoreRoles(nodes); len(got) != 0 {
		t.Errorf("missingCoreRoles = %v, want empty", got)
	}
}
