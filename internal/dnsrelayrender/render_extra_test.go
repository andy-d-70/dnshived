// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package dnsrelayrender

import (
	"testing"

	"dnshived/internal/config"
)

func TestRenderRelayConfig_ExtraInterfaceForTheDNSVIP(t *testing.T) {
	cluster := config.Cluster{Scopes: map[string]config.ScopeConfig{"a": {Parent: "ens19", VLANID: 10}}}
	t.Cleanup(func() { SetExtraInterfaces(nil) })
	base, err := RenderRelayConfig(cluster)
	if err != nil {
		t.Fatal(err)
	}
	SetExtraInterfaces([]string{"ens18", "ens18", ""})
	got, err := RenderRelayConfig(cluster)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.AllowedInterfaces) != len(base.AllowedInterfaces)+1 || got.AllowedInterfaces[len(got.AllowedInterfaces)-1] != "ens18" {
		t.Fatalf("the management interface is added once: %v", got.AllowedInterfaces)
	}
	SetExtraInterfaces(nil)
	if again, _ := RenderRelayConfig(cluster); len(again.AllowedInterfaces) != len(base.AllowedInterfaces) {
		t.Fatal("clearing the extra interfaces restores the original list")
	}
	if _, err := RenderRelayConfig(config.Cluster{}); err == nil {
		t.Fatal("an extra interface must not make a cluster without scopes eligible")
	}
}
