// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package config

import (
	"fmt"
	"strings"
	"testing"
)

func TestPlatform_ServingInterfaces(t *testing.T) {
	tests := []struct {
		name string
		p    *Platform
		want string
	}{
		{"nil", nil, ""},
		{"workers serve by default, management does not", &Platform{Mgmt: "ens18", Workers: []string{"ens19", "ens20"}}, "ens19,ens20"},
		{"management switched on goes last", &Platform{Mgmt: "ens18", Workers: []string{"ens19", "ens20"}, Serving: map[string]bool{"ens18": true}}, "ens19,ens20,ens18"},
		{"a worker switched off drops out", &Platform{Mgmt: "ens18", Workers: []string{"ens19", "ens20"}, Serving: map[string]bool{"ens19": false}}, "ens20"},
		{"one NIC", &Platform{Mgmt: "ens18", Serving: map[string]bool{"ens18": true}}, "ens18"},
		{"one NIC not switched on", &Platform{Mgmt: "ens18"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := strings.Join(tt.p.ServingInterfaces(), ","); got != tt.want {
				t.Errorf("ServingInterfaces = %q, want %q", got, tt.want)
			}
		})
	}
}

func servingCluster(p *Platform, scopes map[string]ScopeConfig) Cluster {
	return Cluster{
		NodeID: "n", Role: RoleCore1, ControlAddr: "10.9.9.1:9443", ClusterID: "c", PSK: "psk", LogLevel: "info", TrustedHosts: []string{"a"}, CoreDNSAddress: "127.0.0.1",
		Platform: p, Scopes: scopes,
	}
}

func untaggedScope(parent string) ScopeConfig {
	return ScopeConfig{Parent: parent, VRRPID: 10, VIP: "10.0.1.1/24", Gateway: "10.0.1.1", NodeIP: "10.0.1.22/24"}
}

func TestValidate_ServingSwitch(t *testing.T) {
	base := func() *Platform {
		return &Platform{Mgmt: "ens18", Workers: []string{"ens19"}}
	}
	t.Run("a scope already on the management interface still loads without the switch", func(t *testing.T) {
		c := servingCluster(base(), map[string]ScopeConfig{"m": untaggedScope("ens18")})
		if err := c.validate(); err != nil && strings.Contains(err.Error(), "serving") {
			t.Fatalf("an existing management scope must keep loading: %v", err)
		}
	})
	t.Run("an unknown interface in the switches is refused", func(t *testing.T) {
		p := base()
		p.Serving = map[string]bool{"eth9": true}
		c := servingCluster(p, nil)
		if err := c.validate(); err == nil || !strings.Contains(err.Error(), "eth9") {
			t.Fatalf("err = %v, want the unknown interface named", err)
		}
	})
	t.Run("an interface cannot stop serving while an active scope is on it", func(t *testing.T) {
		p := base()
		p.Serving = map[string]bool{"ens18": false}
		c := servingCluster(p, map[string]ScopeConfig{"m": untaggedScope("ens18")})
		err := c.validate()
		if err == nil || !strings.Contains(err.Error(), "cannot stop serving") || !strings.Contains(err.Error(), "(m)") {
			t.Fatalf("err = %v, want the active scope named", err)
		}
	})
	t.Run("the refusal counts and names the scopes, capped", func(t *testing.T) {
		p := base()
		p.Serving = map[string]bool{"ens19": false}
		scopes := map[string]ScopeConfig{}
		for i := 0; i < 12; i++ {
			sc := untaggedScope("ens19")
			sc.VLANID = 100 + i
			sc.VRRPID = 10 + i
			sc.VIP = fmt.Sprintf("10.0.%d.1/24", 100+i)
			sc.Gateway = fmt.Sprintf("10.0.%d.1", 100+i)
			sc.NodeIP = fmt.Sprintf("10.0.%d.22/24", 100+i)
			scopes[fmt.Sprintf("s%02d", i)] = sc
		}
		c := servingCluster(p, scopes)
		err := c.validate()
		if err == nil || !strings.Contains(err.Error(), "12 active scope(s)") || !strings.Contains(err.Error(), "and 4 more") {
			t.Fatalf("err = %v, want the count and the cap", err)
		}
	})
	t.Run("an interface may stop serving once every scope on it is disabled", func(t *testing.T) {
		p := base()
		p.Serving = map[string]bool{"ens18": false}
		sc := untaggedScope("ens18")
		sc.DNSMasqDisabled = true
		c := servingCluster(p, map[string]ScopeConfig{"m": sc})
		if err := c.validate(); err != nil && strings.Contains(err.Error(), "serving") {
			t.Fatalf("err = %v, want it accepted: the only scope is disabled", err)
		}
	})
}
