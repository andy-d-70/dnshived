// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"reflect"
	"testing"

	"dnshived/internal/config"
	"dnshived/internal/dhcprelay"
)

func TestRelayStatusEntries_OnlyEnabledScopesCount(t *testing.T) {
	cfg := &config.Cluster{Role: config.RoleCore1, Scopes: map[string]config.ScopeConfig{
		"office": {Parent: "ens19", VLANID: 4},
		"lab":    {Parent: "ens20", VLANID: 20, DNSMasqDisabled: true},
	}}
	relay := &dhcprelay.Config{ClientInterfaces: []dhcprelay.ClientInterfaceConfig{
		{Name: "ens19.4"}, {Name: "ens20.20"}, {Name: "ens19.99"},
	}}
	enabled, labels := relayStatusEntries(cfg, relay)
	if enabled != 1 || !reflect.DeepEqual(labels, []string{"office (ens19.4)"}) {
		t.Errorf("got %d, %v; want 1, [office (ens19.4)]", enabled, labels)
	}
}

func TestRelayStatusEntries_AllDisabledIsZeroDespiteStaleRelayJSON(t *testing.T) {
	cfg := &config.Cluster{Role: config.RoleCore1, Scopes: map[string]config.ScopeConfig{
		"office": {Parent: "ens19", VLANID: 4, DNSMasqDisabled: true},
	}}
	relay := &dhcprelay.Config{ClientInterfaces: []dhcprelay.ClientInterfaceConfig{{Name: "ens19.4"}}}
	if enabled, labels := relayStatusEntries(cfg, relay); enabled != 0 || len(labels) != 0 {
		t.Errorf("got %d, %v; want 0 and no relay interfaces", enabled, labels)
	}
	if enabled, labels := relayStatusEntries(cfg, nil); enabled != 0 || labels != nil {
		t.Errorf("no relay.json: got %d, %v", enabled, labels)
	}
}
