// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"testing"

	"dnshived/internal/config"
)

func TestConstructDNSRelayPlane_NonWorkerRole_ReturnsFalseNoSideEffects(t *testing.T) {
	a := New(config.RoleCore3, "test-arbiter", 1, "psk", "/tmp", testScopes("office"), nil)

	if a.constructDNSRelayPlane() {
		t.Error("constructDNSRelayPlane() = true for an arbiter, want false -- an arbiter must never start dnshived-dnsrelay")
	}
}

// TestConstructDNSRelayPlane_NoScopesConfigured_ReturnsTrueWithoutStarting
// confirms zero configured scopes is treated as "successfully nothing to
// do".
func TestConstructDNSRelayPlane_NoScopesConfigured_ReturnsTrueWithoutStarting(t *testing.T) {
	a := New(config.RoleCore1, "test-worker-a", 1, "psk", "/tmp", map[string]config.ScopeConfig{}, nil)

	if !a.constructDNSRelayPlane() {
		t.Error("constructDNSRelayPlane() = false with zero scopes configured, want true (nothing to do is success, not failure)")
	}
}
