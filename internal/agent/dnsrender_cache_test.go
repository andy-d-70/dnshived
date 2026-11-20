// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"testing"

	"dnshived/internal/config"
)

func TestRenderCoreDNSConfig_RendersAgainOnlyWhenAnInputChanged(t *testing.T) {
	a := New(config.RoleCore1, "test-node", 1, "psk", t.TempDir(), map[string]config.ScopeConfig{}, nil)
	renders := 0
	orig := renderCentralDNS
	defer func() { renderCentralDNS = orig }()
	renderCentralDNS = func(c config.Cluster, address, dataDir string) (string, error) {
		renders++
		return orig(c, address, dataDir)
	}

	first, h1, err := a.renderCoreDNSConfig()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, _, err := a.renderCoreDNSConfig(); err != nil {
			t.Fatal(err)
		}
	}
	if renders != 1 {
		t.Fatalf("an unchanged configuration was rendered %d times, want once", renders)
	}

	changes := []func(){
		func() { a.SetGlobalDNSRecords([]config.DNSRecord{{Name: "x.lan.", Type: "A", Value: "10.0.0.9"}}) },
		func() {
			a.SetLocalDomains([]config.LocalDomain{{Name: "a.lan", Records: []config.LocalDomainHost{{Host: "h", Type: "A", Value: "10.0.0.8"}}}})
		},
		func() { a.SetCentralDNSUpstream([]string{"9.9.9.9"}) },
		func() { a.SetCoreDNSAddress("192.0.2.53") },
		func() { a.SetCoreDNSQueryLogging(true) },
		func() { a.publishScopes(map[string]config.ScopeConfig{}) },
	}
	for i, change := range changes {
		before := renders
		change()
		if _, _, err := a.renderCoreDNSConfig(); err != nil {
			t.Fatal(err)
		}
		if renders != before+1 {
			t.Errorf("change %d did not cause a new render", i)
		}
		if _, _, err := a.renderCoreDNSConfig(); err != nil || renders != before+1 {
			t.Errorf("change %d was rendered twice", i)
		}
	}
	last, h2, _ := a.renderCoreDNSConfig()
	if last == first || h1 == h2 {
		t.Error("the rendered text and its hash must follow the inputs")
	}
}
