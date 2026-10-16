// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"net"
	"testing"
	"time"

	"dnshived/internal/config"
)

func TestCheckPlaneHealth_NotYetReadyScopeIsSkipped(t *testing.T) {
	a := New(config.RoleCore1, "test-node", 1, "psk", "/tmp", testScopes("office"), nil)

	found := a.CheckPlaneHealth()
	if found != nil {
		t.Errorf("found = %v, want nil for a scope that was never marked ready", found)
	}
}

func TestCheckPlaneHealth_MissingInterfaceDemotesReady(t *testing.T) {
	a := New(config.RoleCore1, "test-node", 1, "psk", "/tmp", testScopes("office"), nil)
	a.ready["office"] = time.Now()

	found := a.CheckPlaneHealth()
	if len(found) != 1 {
		t.Fatalf("len(found) = %d, want 1", len(found))
	}
	if found[0].Scope != "office" || found[0].What != "interface" {
		t.Errorf("found[0] = %+v, want Scope=office What=interface", found[0])
	}
	if !found[0].Healable {
		t.Error("a missing interface must be Healable — the a.ready-demotion retry path genuinely fixes it")
	}
	if _, ok := a.ready["office"]; ok {
		t.Error("a.ready[\"office\"] still present — CheckPlaneHealth must demote it so Reconcile's retry path reconstructs it")
	}
}

func TestCheckPlaneHealth_ManyScopesStayScopeSortedOrder(t *testing.T) {
	scopes := map[string]config.ScopeConfig{}
	for i, name := range []string{"zzz-scope", "aaa-scope", "mmm-scope"} {
		scopes[name] = config.ScopeConfig{
			Parent: "ens19", VLANID: 200 + i,
			VIP: "192.168.100.1/24", NodeIP: "192.168.100.22/24",
			DHCPRange: [2]string{"192.168.100.100", "192.168.100.200"},
			Gateway:   "192.168.100.1",
		}
	}
	a := New(config.RoleCore1, "test-node", 1, "psk", "/tmp", scopes, nil)
	for name := range scopes {
		a.ready[name] = time.Now()
	}

	found := a.CheckPlaneHealth()
	if len(found) != 3 {
		t.Fatalf("len(found) = %d, want 3 (all three interfaces are fake and don't exist)", len(found))
	}
	want := []string{"aaa-scope", "mmm-scope", "zzz-scope"}
	for i, f := range found {
		if f.Scope != want[i] {
			t.Errorf("found[%d].Scope = %q, want %q (deterministic scope-sorted order)", i, f.Scope, want[i])
		}
	}
}

func TestCheckPlaneHealth_KeepalivedSkippedWhenNotReady(t *testing.T) {
	a := New(config.RoleCore1, "test-node", 1, "psk", "/tmp", testScopes("office"), nil)
	a.ready["office"] = time.Now() // avoid the interface-missing finding drowning out the assertion

	found := a.CheckPlaneHealth()
	for _, f := range found {
		if f.What == "keepalived" {
			t.Errorf("got a keepalived finding while keepalivedReady was false: %+v", f)
		}
	}
}

func TestAddrsMatch_TrueWhenCIDRIPPresentRegardlessOfMask(t *testing.T) {
	addrs := []net.Addr{
		&net.IPNet{IP: net.ParseIP("172.16.100.22"), Mask: net.CIDRMask(24, 32)},
	}
	if !addrsMatch(addrs, "172.16.100.22/24") {
		t.Error("want true — exact IP present")
	}
	// Mask differences must be ignored (reconcileInterfaceAddrs cares
	// about the address, not exactly how it's expressed).
	if !addrsMatch(addrs, "172.16.100.22/25") {
		t.Error("want true — same IP, different mask must still match")
	}
}

func TestAddrsMatch_FalseWhenIPAbsent(t *testing.T) {
	addrs := []net.Addr{
		&net.IPNet{IP: net.ParseIP("172.16.100.22"), Mask: net.CIDRMask(24, 32)},
	}
	if addrsMatch(addrs, "172.16.100.99/24") {
		t.Error("want false — configured node_ip is not among the real addresses")
	}
}

func TestAddrsMatch_MalformedCIDRDoesNotManufactureFinding(t *testing.T) {
	if !addrsMatch(nil, "not-a-cidr") {
		t.Error("want true (no finding) — a malformed node_ip is a config problem, not this check's to flag")
	}
}

func TestAddrsMatch_EmptyAddrListReturnsFalse(t *testing.T) {
	if addrsMatch(nil, "172.16.100.22/24") {
		t.Error("want false — no real addresses at all cannot match a configured one")
	}
}

func TestLastAppliedGate_UnknownUntilRecorded(t *testing.T) {
	a := New(config.RoleCore1, "test-node", 1, "psk", "/tmp", testScopes("office"), nil)
	if _, known := a.lastGate("office"); known {
		t.Error("want known=false before recordAppliedGate is ever called for this scope")
	}
	a.recordAppliedGate("office", "closed")
	state, known := a.lastGate("office")
	if !known || state != "closed" {
		t.Errorf("lastGate() = (%q, %v), want (\"closed\", true) after recordAppliedGate", state, known)
	}
	a.recordAppliedGate("office", "open")
	state, known = a.lastGate("office")
	if !known || state != "open" {
		t.Errorf("lastGate() = (%q, %v), want (\"open\", true) after a second recordAppliedGate", state, known)
	}
}

func TestShouldSkipInterfaceRebuild(t *testing.T) {
	cases := []struct {
		name       string
		gateState  string // "" = never recorded
		iface      string // "lo" always exists on the test runner; this name never does
		wantSkip   bool
		wantReason string
	}{
		{
			name:      "never recorded — genuinely fresh scope, must build",
			gateState: "", iface: "lo", wantSkip: false,
			wantReason: "no lastGate entry at all (first-ever construction) must never skip",
		},
		{
			name:      "recorded closed — standby scope, retry is harmless either way",
			gateState: "closed", iface: "lo", wantSkip: false,
			wantReason: "a standby scope's retry must still go through createInterface (idempotent, no live service at risk)",
		},
		{
			name:      "recorded open, interface exists — the actual bug scenario",
			gateState: "open", iface: "lo", wantSkip: true,
			wantReason: "dnsmasq-crash-triggered retry of an actively-serving scope must not touch the interface/gate at all",
		},
		{
			name:      "recorded open, interface genuinely gone — must still rebuild",
			gateState: "open", iface: "dnshived-test-missing-9x", wantSkip: false,
			wantReason: "an out-of-band-deleted interface must still be rebuilt (with the correct fail-safe-closed gate), even though this node last believed it was open",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := New(config.RoleCore1, "test-node", 1, "psk", "/tmp", testScopes("office"), nil)
			if tc.gateState != "" {
				a.recordAppliedGate("office", tc.gateState)
			}
			got := a.shouldSkipInterfaceRebuild("office", tc.iface)
			if got != tc.wantSkip {
				t.Errorf("shouldSkipInterfaceRebuild() = %v, want %v — %s", got, tc.wantSkip, tc.wantReason)
			}
		})
	}
}
