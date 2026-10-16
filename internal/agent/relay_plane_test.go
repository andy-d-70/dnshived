// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"testing"

	"dnshived/internal/config"
)

func TestRelayEligibleScopes_ExcludesScopeWithNoNodeIP(t *testing.T) {
	scopes := map[string]config.ScopeConfig{
		"has-ip": {NodeIP: "192.168.10.22/24"},
		"no-ip":  {NodeIP: ""},
	}
	out := relayEligibleScopes(scopes, func(string) bool { return false })

	if _, ok := out["has-ip"]; !ok {
		t.Error("has-ip should be relay-eligible")
	}
	if _, ok := out["no-ip"]; ok {
		t.Error("no-ip must be excluded -- no node_ip to use as giaddr")
	}
}

func TestRelayEligibleScopes_ExcludesScopeWithActiveDnsmasq(t *testing.T) {
	scopes := map[string]config.ScopeConfig{
		"still-old-style": {NodeIP: "192.168.10.22/24"},
	}
	out := relayEligibleScopes(scopes, func(scope string) bool {
		return scope == "still-old-style" // simulates its per-scope dnsmasq still active
	})

	if _, ok := out["still-old-style"]; ok {
		t.Error("a scope whose per-scope dnsmasq is still active must never be registered into the relay -- real socket-bind collision risk on live client traffic")
	}
}

func TestRelayEligibleScopes_ExcludesDisabledScope(t *testing.T) {
	scopes := map[string]config.ScopeConfig{
		"disabled": {NodeIP: "192.168.10.22/24", DNSMasqDisabled: true},
		"enabled":  {NodeIP: "192.168.10.23/24"},
	}
	out := relayEligibleScopes(scopes, func(string) bool { return false })

	if _, ok := out["disabled"]; ok {
		t.Error("an operator-disabled scope must be excluded from relay eligibility -- DNSMasqDisabled means excluded from both DHCP and DNS")
	}
	if _, ok := out["enabled"]; !ok {
		t.Error("enabled should stay relay-eligible")
	}
}

func TestRelayEligibleScopes_IncludesScopeWithNodeIPAndInactiveDnsmasq(t *testing.T) {
	scopes := map[string]config.ScopeConfig{
		"migrated": {NodeIP: "192.168.10.22/24"},
	}
	out := relayEligibleScopes(scopes, func(string) bool { return false })

	if _, ok := out["migrated"]; !ok {
		t.Error("a scope with a real node_ip and no active per-scope dnsmasq should be relay-eligible")
	}
}

func TestRelayEligibleScopes_MixOfEligibleAndIneligible(t *testing.T) {
	scopes := map[string]config.ScopeConfig{
		"eligible-1":   {NodeIP: "192.168.10.22/24"},
		"eligible-2":   {NodeIP: "192.168.11.22/24"},
		"no-node-ip":   {},
		"still-active": {NodeIP: "192.168.12.22/24"},
	}
	out := relayEligibleScopes(scopes, func(scope string) bool {
		return scope == "still-active"
	})

	if len(out) != 2 {
		t.Fatalf("relayEligibleScopes returned %d entries, want 2: %v", len(out), out)
	}
	if _, ok := out["eligible-1"]; !ok {
		t.Error("eligible-1 missing")
	}
	if _, ok := out["eligible-2"]; !ok {
		t.Error("eligible-2 missing")
	}
}

func TestConstructRelayPlane_NonWorkerRole_ReturnsFalseNoSideEffects(t *testing.T) {
	a := New(config.RoleCore3, "test-arbiter", 1, "psk", "/tmp", testScopes("office"), nil)

	if a.constructRelayPlane() {
		t.Error("constructRelayPlane() = true for an arbiter, want false -- an arbiter must never register any scope with the relay")
	}
}

func TestConstructRelayPlane_NoEligibleScopes_ReturnsTrueWithoutStartingRelay(t *testing.T) {
	// No scope has a node_ip -- nothing for the relay to serve yet.
	scopes := map[string]config.ScopeConfig{
		"pending": {Parent: "ens19", VLANID: 100},
	}
	a := New(config.RoleCore1, "test-worker-a", 1, "psk", "/tmp", scopes, nil)

	if !a.constructRelayPlane() {
		t.Error("constructRelayPlane() = false with zero relay-eligible scopes, want true (nothing to do is success, not failure)")
	}
}
