// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"testing"
	"time"

	"dnshived/internal/config"
)

func TestNeighborProbeAllowed(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	if !neighborProbeAllowed("a-test", now) {
		t.Fatal("the first probe passes")
	}
	if neighborProbeAllowed("a-test", now.Add(neighborProbeGap/2)) {
		t.Fatal("a second probe inside the gap is refused")
	}
	if !neighborProbeAllowed("b-test", now) {
		t.Fatal("another scope has its own gap")
	}
	if !neighborProbeAllowed("a-test", now.Add(neighborProbeGap)) {
		t.Fatal("after the gap the scope may probe again")
	}
}

func TestScopeNeighborView_NeedsAScopeWithAnInterface(t *testing.T) {
	if _, _, _, ok := scopeNeighborView(config.ScopeConfig{}); ok {
		t.Error("an empty scope has no view")
	}
	if _, _, _, ok := scopeNeighborView(config.ScopeConfig{Parent: "nosuchif", VLANID: 7, VIP: "192.0.2.254/24"}); ok {
		t.Error("a scope whose interface is missing has no view")
	}
}
