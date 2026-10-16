// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"testing"

	"dnshived/internal/config"
)

func TestGetJournalTail_RejectsUnlistedUnit(t *testing.T) {
	a := New(config.RoleCore1, "test-node", 1, "psk", "/tmp", nil, nil)
	if _, err := a.GetJournalTail("sshd.service", 10); err == nil {
		t.Error("expected an error for a unit outside AllowedJournalUnits, got nil")
	}
}

func TestGetJournalTail_AllowedUnitsMatchTheHelperSFixedSet(t *testing.T) {
	want := []string{
		"dnshived.service", "dnshived-web.service", "dnshived-helper.service",
		"dnshived-relay.service", "dnshived-dnsrelay.service",
		"dnshived-keepalived.service", "dnshived-keepalived-mgmt.service",
	}
	if len(AllowedJournalUnits) != len(want) {
		t.Errorf("AllowedJournalUnits has %d entries, want exactly %d — keep this in sync with cmd/dnshived-helper's own copy", len(AllowedJournalUnits), len(want))
	}
	for _, u := range want {
		if !AllowedJournalUnits[u] {
			t.Errorf("expected %s in AllowedJournalUnits", u)
		}
	}
}
