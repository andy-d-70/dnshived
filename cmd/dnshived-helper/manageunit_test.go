// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import "testing"

func TestManageUnitEnableNowAllowlist(t *testing.T) {
	for _, unit := range []string{"dnshived-probe.service", "dnshived-probe-helper.service", "dnshived-web.service"} {
		if !manageUnitAllowed["enable-now"][unit] {
			t.Errorf("enable-now not allowed for %s", unit)
		}
	}
	for _, unit := range []string{"dnshived-relay.service", "dnshived-keepalived.service"} {
		if manageUnitAllowed["enable-now"][unit] {
			t.Errorf("enable-now allowed for %s, want denied", unit)
		}
	}
}
