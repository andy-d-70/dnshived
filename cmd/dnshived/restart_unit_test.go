// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import "testing"

// TestIsDnsmasqUnit_MatchesOnlyTheRealPattern pins the exact allowlist
// shape POST /api/v1/daemons/{unit}/restart dispatches on.
func TestIsDnsmasqUnit_MatchesOnlyTheRealPattern(t *testing.T) {
	cases := []struct {
		unit string
		want bool
	}{
		{"dnshived-dnsmasq@office.service", true},
		{"dnshived-dnsmasq@rw-100.service", true},
		{"dnshived-dnsmasq@.service", true}, // empty scope — caller rejects via the config lookup, not here
		{"dnshived-dnsmasq@office", false},  // missing .service suffix
		{"dnshived.service", false},
		{"dnshived-keepalived.service", false},
		{"dnshived-helper.service", false},
	}
	for _, tc := range cases {
		if got := isDnsmasqUnit(tc.unit); got != tc.want {
			t.Errorf("isDnsmasqUnit(%q) = %v, want %v", tc.unit, got, tc.want)
		}
	}
}

// TestScopeFromDnsmasqUnit_ExtractsExactScopeName confirms the scope name
// extracted is exactly what the caller then validates against
// currentConfig.Load().Scopes.
func TestScopeFromDnsmasqUnit_ExtractsExactScopeName(t *testing.T) {
	cases := map[string]string{
		"dnshived-dnsmasq@office.service":   "office",
		"dnshived-dnsmasq@rw-100.service":   "rw-100",
		"dnshived-dnsmasq@av-dante.service": "av-dante",
	}
	for unit, want := range cases {
		if got := scopeFromDnsmasqUnit(unit); got != want {
			t.Errorf("scopeFromDnsmasqUnit(%q) = %q, want %q", unit, got, want)
		}
	}
}
