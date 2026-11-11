// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"testing"
	"time"
)

func TestSettleFilter_HoldsSettlingWarningsUntilTheyPersist(t *testing.T) {
	tr := &settleTracker{first: map[string]time.Time{}}
	t0 := time.Unix(1_000_000, 0)
	noToken := "NO TOKEN: scope dante-000 served by core-2 but no arbiter token exists"
	skew := "CLOCK SKEW: n1 is 7.0s off from core-2"
	noAnswer := probeIssue{Scope: "dante-016", Worker: "probe", DNSText: "DNS✔", DHCPText: "DHCP-NONE", Detail: "[DHCP: no answer]"}
	rogue := probeIssue{Scope: "x", Worker: "probe", DHCPText: "DHCP-NONE", Rogue: true}

	c, p := tr.settleFilter(t0, []string{noToken, skew}, []probeIssue{noAnswer, rogue})
	if len(c) != 1 || c[0] != skew {
		t.Errorf("first sight: only the clock skew shows, got %v", c)
	}
	if len(p) != 1 || !p[0].Rogue {
		t.Errorf("first sight: a rogue DHCP server is never held back, the no-answer is: %+v", p)
	}

	c, p = tr.settleFilter(t0.Add(29*time.Second), []string{noToken, skew}, []probeIssue{noAnswer, rogue})
	if len(c) != 1 || len(p) != 1 {
		t.Errorf("after 29 s both are still held: %v %+v", c, p)
	}
	c, p = tr.settleFilter(t0.Add(31*time.Second), []string{noToken, skew}, []probeIssue{noAnswer, rogue})
	if len(c) != 2 || len(p) != 2 {
		t.Errorf("after 31 s they show: %v %+v", c, p)
	}

	// it goes away and comes back: the grace starts again
	tr.settleFilter(t0.Add(40*time.Second), []string{skew}, nil)
	c, _ = tr.settleFilter(t0.Add(50*time.Second), []string{noToken, skew}, nil)
	if len(c) != 1 {
		t.Errorf("a warning that reappears is held again, got %v", c)
	}
	if len(tr.first) != 1 {
		t.Errorf("tracker keeps %d keys, want only the one present", len(tr.first))
	}
}

func TestSettleFilter_NothingToHoldChangesNothing(t *testing.T) {
	tr := &settleTracker{first: map[string]time.Time{}}
	in := []string{"VERSION MISMATCH: a b", "plain"}
	c, p := tr.settleFilter(time.Unix(5, 0), in, nil)
	if len(c) != 2 || p != nil {
		t.Errorf("got %v %v", c, p)
	}
	if len(tr.first) != 0 {
		t.Error("kinds that are not settling are never tracked")
	}
}

func TestSettleFilter_ManyKeysAreIndependent(t *testing.T) {
	tr := &settleTracker{first: map[string]time.Time{}}
	t0 := time.Unix(100, 0)
	a := "NO TOKEN: scope a served by core-1 but no arbiter token exists"
	b := "NO TOKEN: scope b served by core-1 but no arbiter token exists"
	tr.settleFilter(t0, []string{a}, nil)
	c, _ := tr.settleFilter(t0.Add(31*time.Second), []string{a, b}, nil)
	if len(c) != 1 || c[0] != a {
		t.Errorf("a has persisted, b is new: got %v", c)
	}
}
