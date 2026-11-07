// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dnshived/internal/config"
)

func TestRenderKeepalivedConfigAll_SkipsDisabledScope(t *testing.T) {
	scopes := map[string]config.ScopeConfig{
		"office": {Parent: "eth1", VLANID: 10, VIP: "192.0.2.1/24", VRRPID: 10, PreferredWorker: config.RoleCore1},
		"guest":  {Parent: "eth1", VLANID: 20, VIP: "198.51.100.1/24", VRRPID: 20, PreferredWorker: config.RoleCore1, DNSMasqDisabled: true},
	}
	a := &Agent{dataDir: t.TempDir(), role: config.RoleCore1}
	a.scopes.Store(&scopes)
	ready := map[string]bool{"office": true, "guest": true}
	if err := a.renderKeepalivedConfigAll(nil, ready); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(a.dataDir, "keepalived.conf"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	if !strings.Contains(got, "DNSHIVED_office") || !strings.Contains(got, "192.0.2.1/24") {
		t.Errorf("enabled scope missing from keepalived.conf:\n%s", got)
	}
	if strings.Contains(got, "DNSHIVED_guest") || strings.Contains(got, "198.51.100.1") {
		t.Errorf("disabled scope still has a vrrp_instance or VIP:\n%s", got)
	}
}

func TestRenderKeepalivedConfigAll_AllDisabledWritesNoInstances(t *testing.T) {
	scopes := map[string]config.ScopeConfig{
		"office": {Parent: "eth1", VLANID: 10, VIP: "192.0.2.1/24", VRRPID: 10, DNSMasqDisabled: true},
	}
	a := &Agent{dataDir: t.TempDir(), role: config.RoleCore1}
	a.scopes.Store(&scopes)
	if err := a.renderKeepalivedConfigAll(nil, map[string]bool{"office": true}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(a.dataDir, "keepalived.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "vrrp_instance") {
		t.Errorf("an instance was rendered:\n%s", data)
	}
}
