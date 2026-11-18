// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package config

import (
	"reflect"
	"testing"
)

func TestAccessAlways(t *testing.T) {
	c := Cluster{
		ControlAddr: "192.0.2.22:9443",
		Peers:       []string{"192.0.2.23:9443", "192.0.2.24:9443", "not-an-address"},
		MgmtVIP:     &MgmtVIPConfig{VIP: "192.0.2.100/24"},
		Scopes: map[string]ScopeConfig{
			"a": {VIP: "198.51.100.1/24", NodeIP: "198.51.100.22/24", Gateway: "198.51.100.1", NodeIPOverrides: map[string]string{"core-2": "198.51.100.23/24"}},
			"b": {VIP: "203.0.113.1/24", Gateway: "203.0.113.254"},
		},
	}
	want := []string{"192.0.2.100", "192.0.2.22", "192.0.2.23", "192.0.2.24", "198.51.100.1", "198.51.100.22", "198.51.100.23", "203.0.113.1", "203.0.113.254"}
	if got := c.AccessAlways(); !reflect.DeepEqual(got, want) {
		t.Errorf("AccessAlways = %v, want %v", got, want)
	}
	if got := (&Cluster{}).AccessAlways(); len(got) != 0 {
		t.Errorf("an empty cluster has no always-allowed addresses, got %v", got)
	}
}
