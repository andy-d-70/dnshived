// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"strings"
	"testing"

	"dnshived/internal/config"
)

func TestApplyCoreDNSConfig_ChangesWithScopeContent(t *testing.T) {
	dir := t.TempDir()
	scopes := testScopes("office")
	a := New(config.RoleCore1, "test-node", 1, "", dir, scopes, nil)

	restarted, _, err := a.applyCoreDNSConfig()
	if !restarted {
		t.Fatal("first call: restarted = false, want true — an empty hash must always be treated as changed")
	}
	if err == nil || !strings.Contains(err.Error(), "restart") {
		t.Fatalf("first call: err = %v, want a restart error (no real unit in this sandbox)", err)
	}

	restarted2, _, err2 := a.applyCoreDNSConfig()
	if !restarted2 || err2 == nil {
		t.Error("second call (identical content): restarted/err = false/nil, want a retried restart attempt — a failed restart must never be committed")
	}
}

// TestApplyCoreDHCPConfig_ChangesWithScopeContent mirrors
// TestApplyCoreDNSConfig_ChangesWithScopeContent for the DHCP side
// (dhcpcentralrender.Render).
func TestApplyCoreDHCPConfig_ChangesWithScopeContent(t *testing.T) {
	dir := t.TempDir()
	scopes := testScopes("office")
	a := New(config.RoleCore1, "test-node", 1, "", dir, scopes, nil)

	restarted, _, err := a.applyCoreDHCPConfig()
	if !restarted {
		t.Fatal("restarted = false, want true — an empty hash must always be treated as changed")
	}
	if err == nil || !strings.Contains(err.Error(), "restart") {
		t.Fatalf("err = %v, want a restart error (no real unit in this sandbox)", err)
	}
}

// TestApplyRelayConfig_ChangesWithScopeSet pins the hash-compare/
// restart-on-change contract for relay.json.
func TestApplyRelayConfig_ChangesWithScopeSet(t *testing.T) {
	dir := t.TempDir()
	scopes := testScopes("office")
	a := New(config.RoleCore1, "test-node", 1, "", dir, scopes, nil)

	_, _, err := a.applyRelayConfig(scopes)
	if err == nil {
		t.Fatal("err = nil, want a real error — an empty hash must always be treated as changed and attempt to apply")
	}
	if !strings.Contains(err.Error(), "write relay config") && !strings.Contains(err.Error(), "restart") {
		t.Errorf("err = %v, want a write-relay-config or restart error", err)
	}
}

// TestApplyDNSRelayConfig_ChangesWithScopeSet mirrors
// TestApplyRelayConfig_ChangesWithScopeSet exactly.
func TestApplyDNSRelayConfig_ChangesWithScopeSet(t *testing.T) {
	dir := t.TempDir()
	scopes := testScopes("office")
	a := New(config.RoleCore1, "test-node", 1, "", dir, scopes, nil)

	_, _, err := a.applyDNSRelayConfig(scopes)
	if err == nil {
		t.Fatal("err = nil, want a real error — an empty hash must always be treated as changed and attempt to apply")
	}
	if !strings.Contains(err.Error(), "write dnsrelay config") && !strings.Contains(err.Error(), "restart") {
		t.Errorf("err = %v, want a write-dnsrelay-config or restart error", err)
	}
}
