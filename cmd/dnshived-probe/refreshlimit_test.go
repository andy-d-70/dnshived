// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import "testing"

func TestRefreshLimiter_RejectsConcurrentTriggerForSameScope(t *testing.T) {
	l := newRefreshLimiter()

	if !l.tryStart("rw-100") {
		t.Fatal("first tryStart for rw-100 = false, want true")
	}
	if l.tryStart("rw-100") {
		t.Error("second tryStart for rw-100 (still in flight) = true, want false")
	}
	l.finish("rw-100")
	if !l.tryStart("rw-100") {
		t.Error("tryStart for rw-100 after finish = false, want true")
	}
}

func TestRefreshLimiter_DifferentScopesIndependent(t *testing.T) {
	l := newRefreshLimiter()

	if !l.tryStart("rw-100") {
		t.Fatal("tryStart rw-100 = false, want true")
	}
	if !l.tryStart("rw-101") {
		t.Error("tryStart rw-101 while rw-100 is in flight = false, want true — different scopes must not block each other")
	}
}
