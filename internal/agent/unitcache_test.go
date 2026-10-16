// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"testing"

	"dnshived/internal/daemonstatus"
)

func TestUnitActions_InvalidateUnitSnapshot(t *testing.T) {
	a := &Agent{}
	actions := map[string]func(){
		"restartRelayUnit":        func() { a.restartRelayUnit() },
		"stopDNSRelayUnit":        func() { a.stopDNSRelayUnit() },
		"restartCoreDHCPUnit":     func() { a.restartCoreDHCPUnit() },
		"reloadCoreDNSUnit":       func() { a.reloadCoreDNSUnit() },
		"ensureKeepalivedRunning": func() { a.ensureKeepalivedRunning() },
		"stopDnsmasqUnit":         func() { a.stopDnsmasqUnit("office") },
	}
	for name, act := range actions {
		queries := 0
		a.units = nil
		a.unitsOnce.Do(func() {})
		a.units = daemonstatus.NewCacheForTest(func([]string) map[string]daemonstatus.Status {
			queries++
			return map[string]daemonstatus.Status{"dnshived-relay.service": {ActiveState: "active"}}
		})
		a.unitActive("dnshived-relay.service")
		act()
		a.unitActive("dnshived-relay.service")
		if queries != 2 {
			t.Errorf("%s: %d snapshot queries around the action, want 2 (action must invalidate)", name, queries)
		}
	}
}
