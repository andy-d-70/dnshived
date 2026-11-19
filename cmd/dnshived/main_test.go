// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"testing"

	"dnshived/internal/config"
)

func TestMgmtIfaceFromConfig_NilPlatformReturnsEmpty(t *testing.T) {
	cfg := &config.Cluster{Platform: nil}
	if got := mgmtIfaceFromConfig(cfg); got != "" {
		t.Errorf("mgmtIfaceFromConfig = %q, want empty string for a nil Platform", got)
	}
}

// TestMgmtIfaceFromConfig_ReturnsConfiguredMgmtInterface checks the
// normal, non-nil case.
func TestMgmtIfaceFromConfig_ReturnsConfiguredMgmtInterface(t *testing.T) {
	cfg := &config.Cluster{Platform: &config.Platform{Mgmt: "ens18"}}
	if got := mgmtIfaceFromConfig(cfg); got != "ens18" {
		t.Errorf("mgmtIfaceFromConfig = %q, want %q", got, "ens18")
	}
}

func TestConfigUpdateApplyTo_ParkedScopes(t *testing.T) {
	parkedOf := func(body string) config.Cluster {
		c := config.Cluster{ParkedScopes: map[string]config.ScopeConfig{"keep": {VLANID: 1}}}
		var u configUpdate
		if err := json.Unmarshal([]byte(body), &u); err != nil {
			t.Fatal(err)
		}
		u.applyTo(&c)
		return c
	}
	if c := parkedOf(`{}`); len(c.ParkedScopes) != 1 {
		t.Error("a sender without the field must leave the parked scopes alone")
	}
	if c := parkedOf(`{"parked_scopes":{}}`); c.ParkedScopes != nil {
		t.Error("an empty map clears the parked scopes")
	}
	if c := parkedOf(`{"parked_scopes":{"a":{"vlan_id":5}}}`); len(c.ParkedScopes) != 1 || c.ParkedScopes["a"].VLANID != 5 {
		t.Errorf("a map replaces the parked scopes: %v", c.ParkedScopes)
	}
}
