// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import "testing"

func TestMonotonicIdentity_AppliesForwardMovement(t *testing.T) {
	var pushedEpoch, pushedGen uint64
	id := newMonotonicIdentity(1, 1, func(e, g uint64) { pushedEpoch, pushedGen = e, g })

	if !id.applyEpoch(2) {
		t.Fatal("expected a strictly-newer epoch to apply")
	}
	if pushedEpoch != 2 || pushedGen != 1 {
		t.Fatalf("expected push (2,1), got (%d,%d)", pushedEpoch, pushedGen)
	}

	if !id.applyGeneration(5) {
		t.Fatal("expected a strictly-newer generation to apply")
	}
	if pushedEpoch != 2 || pushedGen != 5 {
		t.Fatalf("expected push (2,5), got (%d,%d)", pushedEpoch, pushedGen)
	}
}

func TestMonotonicIdentity_DropsOutOfOrderCallback(t *testing.T) {
	var pushCount int
	var pushedEpoch uint64
	id := newMonotonicIdentity(5, 0, func(e, g uint64) {
		pushCount++
		pushedEpoch = e
	})

	if !id.applyEpoch(7) {
		t.Fatal("expected epoch 7 to apply over baseline 5")
	}
	if pushedEpoch != 7 {
		t.Fatalf("expected pushed epoch 7, got %d", pushedEpoch)
	}

	if id.applyEpoch(6) {
		t.Fatal("a stale, out-of-order epoch must not apply")
	}
	if pushedEpoch != 7 {
		t.Fatalf("stale callback regressed the announced epoch: got %d, want 7", pushedEpoch)
	}
	if pushCount != 1 {
		t.Fatalf("expected exactly one push (the stale one must not push at all), got %d", pushCount)
	}

	// An equal value (redelivery, not staleness) must also be a no-op —
	// epoch only ever strictly increases at the source.
	if id.applyEpoch(7) {
		t.Fatal("a non-increasing epoch must not re-apply")
	}
	if pushCount != 1 {
		t.Fatalf("redelivered equal epoch must not push again, got pushCount=%d", pushCount)
	}
}

func TestMonotonicIdentity_GenerationIndependentOfEpoch(t *testing.T) {
	var pushedEpoch, pushedGen uint64
	id := newMonotonicIdentity(3, 10, func(e, g uint64) { pushedEpoch, pushedGen = e, g })

	if id.applyGeneration(9) {
		t.Fatal("a stale generation must not apply")
	}
	if !id.applyGeneration(11) {
		t.Fatal("expected generation 11 to apply over baseline 10")
	}
	if pushedEpoch != 3 || pushedGen != 11 {
		t.Fatalf("expected push (3,11), got (%d,%d)", pushedEpoch, pushedGen)
	}
}
