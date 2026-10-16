// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"reflect"
	"testing"

	"dnshived/internal/config"
)

func platformCfg() config.Cluster {
	return config.Cluster{Platform: &config.Platform{
		Mgmt:            "ens18",
		Workers:         []string{"ens19", "ens20"},
		WorkerOverrides: map[string]map[string]string{"core-1": {"ens19": "eno1"}, "core-3": {"ens19": "old1"}},
		MgmtOverrides:   map[string]string{"core-3": "oldmgmt"},
	}}
}

func TestWithRoleInterfaces_ReplacesOnlyThatRole(t *testing.T) {
	cfg := platformCfg()
	got := withRoleInterfaces(cfg, "core-3", &roleInterfaces{
		Workers: map[string]string{"ens19": "eth1", "ens20": "ens20"},
		Mgmt:    "eth0",
	})
	wantWorkers := map[string]map[string]string{"core-1": {"ens19": "eno1"}, "core-3": {"ens19": "eth1"}}
	if !reflect.DeepEqual(got.Platform.WorkerOverrides, wantWorkers) {
		t.Errorf("WorkerOverrides = %v, want %v", got.Platform.WorkerOverrides, wantWorkers)
	}
	if got.Platform.MgmtOverrides["core-3"] != "eth0" {
		t.Errorf("MgmtOverrides = %v, want core-3 -> eth0", got.Platform.MgmtOverrides)
	}
	if cfg.Platform.WorkerOverrides["core-3"]["ens19"] != "old1" || cfg.Platform.MgmtOverrides["core-3"] != "oldmgmt" {
		t.Error("withRoleInterfaces mutated the original config")
	}
}

func TestWithRoleInterfaces_NilClearsRole(t *testing.T) {
	got := withRoleInterfaces(platformCfg(), "core-3", nil)
	if _, ok := got.Platform.WorkerOverrides["core-3"]; ok {
		t.Errorf("core-3 worker overrides still present: %v", got.Platform.WorkerOverrides)
	}
	if got.Platform.MgmtOverrides != nil {
		t.Errorf("MgmtOverrides = %v, want nil", got.Platform.MgmtOverrides)
	}
	if got.Platform.WorkerOverrides["core-1"]["ens19"] != "eno1" {
		t.Error("another role's overrides were dropped")
	}
}

func TestWithRoleInterfaces_MatchingNamesStoreNothing(t *testing.T) {
	cfg := config.Cluster{Platform: &config.Platform{Mgmt: "ens18", Workers: []string{"ens19"}}}
	got := withRoleInterfaces(cfg, "core-2", &roleInterfaces{Workers: map[string]string{"ens19": "ens19"}, Mgmt: "ens18"})
	if got.Platform.WorkerOverrides != nil || got.Platform.MgmtOverrides != nil {
		t.Errorf("overrides = %v / %v, want none for identical names", got.Platform.WorkerOverrides, got.Platform.MgmtOverrides)
	}
}

func TestResetRoleAddressing_ClearsRoleInterfaces(t *testing.T) {
	got := resetRoleAddressing(platformCfg(), "core-3", "")
	if _, ok := got.Platform.WorkerOverrides["core-3"]; ok || got.Platform.MgmtOverrides["core-3"] != "" {
		t.Errorf("role reset kept core-3 interfaces: %v %v", got.Platform.WorkerOverrides, got.Platform.MgmtOverrides)
	}
}

func TestPlatformResolveMgmt(t *testing.T) {
	p := platformCfg().Platform
	if got := p.ResolveMgmt("core-3"); got != "oldmgmt" {
		t.Errorf("ResolveMgmt(core-3) = %q", got)
	}
	if got := p.ResolveMgmt("core-1"); got != "ens18" {
		t.Errorf("ResolveMgmt(core-1) = %q", got)
	}
}
