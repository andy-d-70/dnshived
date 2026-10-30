// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"strings"
	"testing"

	"dnshived/internal/config"
)

func moveTestCluster() config.Cluster {
	return config.Cluster{
		Platform: &config.Platform{Workers: []string{"ens19", "ens20"}},
		Scopes: map[string]config.ScopeConfig{
			"office": {Parent: "ens19", VLANID: 110},
			"guest":  {Parent: "ens19", VLANID: 120},
			"lab":    {Parent: "ens20", VLANID: 110},
		},
	}
}

func TestValidateScopeMove(t *testing.T) {
	cases := []struct {
		name    string
		scope   string
		parent  string
		vlan    int
		wantErr string
	}{
		{name: "new vlan on same parent", scope: "office", parent: "ens19", vlan: 130},
		{name: "free vlan on other parent", scope: "office", parent: "ens20", vlan: 120},
		{name: "vlan used on other parent", scope: "office", parent: "ens20", vlan: 110, wantErr: "already used by scope lab"},
		{name: "nothing to move", scope: "office", parent: "ens19", vlan: 110, wantErr: "nothing to move"},
		{name: "vlan above range", scope: "office", parent: "ens19", vlan: 4095, wantErr: "between 0 and 4094"},
		{name: "negative vlan", scope: "office", parent: "ens19", vlan: -1, wantErr: "between 0 and 4094"},
		{name: "unknown parent", scope: "office", parent: "ens99", vlan: 130, wantErr: "not a trunk interface"},
		{name: "vlan used on same parent", scope: "office", parent: "ens19", vlan: 120, wantErr: "already used by scope guest"},
		{name: "missing scope", scope: "nope", parent: "ens19", vlan: 130, wantErr: "not present"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateScopeMove(moveTestCluster(), tc.scope, tc.parent, tc.vlan)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateScopeMove = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("validateScopeMove = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}
