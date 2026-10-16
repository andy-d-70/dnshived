// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"strings"
	"testing"

	"dnshived/internal/agent"
)

func TestFormatPlaneHealthMsg_IncludesScope(t *testing.T) {
	msg := formatPlaneHealthMsg(agent.PlaneHealth{
		Scope: "office", What: "interface", Detail: "ens19.100 no longer exists",
	})
	want := "scope office: interface ens19.100 no longer exists"
	if msg != want {
		t.Errorf("msg = %q, want %q", msg, want)
	}
}

func TestFormatPlaneHealthMsg_NodeWideFindingOmitsScopePrefix(t *testing.T) {
	// Scope is empty for the node-wide consolidated keepalived finding —
	// "scope : ..." would read as a bug, not infrastructure.
	msg := formatPlaneHealthMsg(agent.PlaneHealth{
		What: "keepalived", Detail: "dnshived-keepalived.service is inactive",
	})
	if strings.HasPrefix(msg, "scope") {
		t.Errorf("msg = %q, want no scope prefix for a node-wide finding", msg)
	}
}

func TestPlaneHealthKey_SameScopeAndWhatIsSameKey(t *testing.T) {
	a := planeHealthKey(agent.PlaneHealth{Scope: "office", What: "interface", Detail: "first detail"})
	b := planeHealthKey(agent.PlaneHealth{Scope: "office", What: "interface", Detail: "different detail text"})
	if a != b {
		t.Errorf("keys differ (%q vs %q) despite identical Scope/What — detail text must not affect identity", a, b)
	}
}

func TestPlaneHealthKey_DifferentWhatIsDifferentKey(t *testing.T) {
	a := planeHealthKey(agent.PlaneHealth{Scope: "office", What: "interface"})
	b := planeHealthKey(agent.PlaneHealth{Scope: "office", What: "dnsmasq"})
	if a == b {
		t.Error("interface and dnsmasq findings for the same scope must not collide on the same key")
	}
}

func TestDriftActionText_HealableSaysReconstructing(t *testing.T) {
	got := driftActionText(agent.PlaneHealth{What: "interface", Healable: true})
	if got != "reconstructing" {
		t.Errorf("driftActionText = %q, want %q", got, "reconstructing")
	}
}

func TestDriftActionText_NotHealableSaysReportOnly(t *testing.T) {
	for _, what := range []string{"gate", "gate_vrrp_coherence", "enablement"} {
		got := driftActionText(agent.PlaneHealth{What: what, Healable: false})
		if got == "reconstructing" {
			t.Errorf("driftActionText(%q) = %q, must never claim reconstructing for a non-healable finding", what, got)
		}
	}
}

func TestPlaneWarningStore_StringsEmptyWhenNoFindings(t *testing.T) {
	s := &planeWarningStore{}
	s.set(nil)
	if got := s.strings(); got != nil {
		t.Errorf("strings() = %v, want nil for no findings", got)
	}
}
