// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"os"
	"testing"

	"dnshived/internal/config"
)

func TestScopeConfigRendered(t *testing.T) {
	withRange := config.ScopeConfig{DHCPRange: [2]string{"10.0.0.100", "10.0.0.200"}}
	tests := []struct {
		name  string
		scope string
		sc    config.ScopeConfig
		dns   bool
		dhcp  string
		want  bool
	}{
		{"DHCP and DNS off needs nothing rendered", "office", config.ScopeConfig{DNSMasqDisabled: true}, false, "", true},
		{"nothing rendered yet", "office", withRange, false, "", false},
		{"DNS rendered, DHCP file missing", "office", withRange, true, "", false},
		{"scope left out of the DHCP file", "office", withRange, true, "dhcp-range=set:other,10.1.0.100,10.1.0.200,255.255.255.0,12h\n", false},
		{"a longer scope name is not this scope", "office", withRange, true, "dhcp-range=set:office2,10.1.0.100,10.1.0.200,255.255.255.0,12h\n", false},
		{"scope present in both files", "office", withRange, true, "dhcp-range=set:office,10.0.0.100,10.0.0.200,255.255.255.0,12h\n", true},
		{"DNS only scope without a range", "office", config.ScopeConfig{}, true, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Agent{dataDir: t.TempDir()}
			if tt.dns {
				if err := os.WriteFile(coreDNSConfigPath(a.dataDir), []byte("port=53\n"), 0o640); err != nil {
					t.Fatal(err)
				}
			}
			if tt.dhcp != "" {
				if err := os.WriteFile(coreDHCPConfigPath(a.dataDir), []byte(tt.dhcp), 0o640); err != nil {
					t.Fatal(err)
				}
			}
			if got := a.scopeConfigRendered(tt.scope, tt.sc); got != tt.want {
				t.Errorf("scopeConfigRendered = %v, want %v", got, tt.want)
			}
		})
	}
}
