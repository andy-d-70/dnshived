// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"testing"
	"time"

	"dnshived/internal/config"
)

func TestScopeNeighborView_IsCachedForAShortTime(t *testing.T) {
	neighborViews.mu.Lock()
	neighborViews.m = nil
	neighborViews.mu.Unlock()
	now := time.Unix(1000, 0)
	neighborNow = func() time.Time { return now }
	defer func() { neighborNow = time.Now }()

	sc := config.ScopeConfig{Parent: "nonexistent0", VLANID: 7, VIP: "192.0.2.254/24"}
	if _, _, _, ok := scopeNeighborView(sc); ok {
		t.Fatal("an interface that does not exist has no view")
	}
	neighborViews.mu.Lock()
	n := len(neighborViews.m)
	neighborViews.mu.Unlock()
	if n != 1 {
		t.Fatalf("the answer, a miss included, must be kept: %d entries", n)
	}
	neighborViews.mu.Lock()
	for k, e := range neighborViews.m {
		e.iface = "from-the-cache"
		e.ok = true
		neighborViews.m[k] = e
	}
	neighborViews.mu.Unlock()
	if iface, _, _, ok := scopeNeighborView(sc); !ok || iface != "from-the-cache" {
		t.Error("a call within the time to live must be served from the cache")
	}
	now = now.Add(neighborViewTTL + time.Second)
	if _, _, _, ok := scopeNeighborView(sc); ok {
		t.Error("after the time to live the interface is read again")
	}
	if _, _, _, ok := scopeNeighborView(config.ScopeConfig{}); ok {
		t.Error("a scope without an interface has no view")
	}
}
