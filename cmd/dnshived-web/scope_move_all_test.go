// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"strings"
	"testing"

	"dnshived/internal/config"
)

func moveScope(parent string, vlan, vrrp int, net string) config.ScopeConfig {
	return config.ScopeConfig{
		Parent: parent, VLANID: vlan, VRRPID: vrrp, PreferredWorker: config.RoleCore1,
		VIP: "10.0." + net + ".1/24", Gateway: "10.0." + net + ".1", NodeIP: "10.0." + net + ".22/24",
	}
}

func moveCluster() config.Cluster {
	return config.Cluster{
		Platform: &config.Platform{Mgmt: "ens18", Workers: []string{"ens19", "ens20"}},
		Scopes: map[string]config.ScopeConfig{
			"a": moveScope("ens19", 10, 1, "10"),
			"b": moveScope("ens19", 11, 2, "11"),
			"c": moveScope("ens20", 12, 3, "12"),
		},
	}
}

func TestPlanMoveAll_CleanMoveKeepsEverythingButTheParent(t *testing.T) {
	plan, err := planMoveAll(moveCluster(), "ens19", "ens20")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Rows) != 2 || plan.Conflicts != 0 {
		t.Fatalf("rows=%d conflicts=%d, want 2 scopes and no conflict: %+v", len(plan.Rows), plan.Conflicts, plan.Rows)
	}
	for _, name := range []string{"a", "b"} {
		got, orig := plan.Moved[name], moveCluster().Scopes[name]
		if got.Parent != "ens20" || got.VLANID != orig.VLANID || got.VIP != orig.VIP || got.NodeIP != orig.NodeIP {
			t.Errorf("%s = %+v, want only the parent changed", name, got)
		}
	}
}

func TestPlanMoveAll_VLANAlreadyUsedOnTheTargetIsAConflictAndNothingIsRenumbered(t *testing.T) {
	c := moveCluster()
	c.Scopes["c"] = moveScope("ens20", 10, 3, "12")

	plan, err := planMoveAll(c, "ens19", "ens20")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Conflicts != 1 {
		t.Fatalf("conflicts = %d, want 1: %+v", plan.Conflicts, plan.Rows)
	}
	if plan.Moved["a"].VLANID != 10 {
		t.Error("the VLAN ID must stay as it is: the operator resolves a clash by hand")
	}
}

func TestPlanMoveAll_TwoMovedScopesOnTheSameVLANConflictWithEachOther(t *testing.T) {
	c := moveCluster()
	c.Scopes["c"] = moveScope("ens20", 12, 3, "12")
	c.Scopes["d"] = moveScope("ens19", 10, 4, "13")
	c.Scopes["a"] = moveScope("ens20", 10, 1, "10")

	plan, err := planMoveAll(c, "ens19", "ens20")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Conflicts == 0 {
		t.Fatalf("rows %+v, want the VLAN 10 clash with the scope already on ens20", plan.Rows)
	}
}

func TestPlanMoveAll_Refusals(t *testing.T) {
	c := moveCluster()
	tests := []struct{ name, from, to, want string }{
		{"same interface", "ens19", "ens19", "same interface"},
		{"nothing on the source", "ens18", "ens20", "no scope is on"},
		{"target does not serve", "ens19", "ens18", "not a serving interface"},
		{"unknown target", "ens19", "eth9", "not a serving interface"},
		{"empty", "", "ens20", "choose both"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := planMoveAll(c, tt.from, tt.to); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestPlanMoveAll_TaggedScopesCannotGoToTheManagementInterface(t *testing.T) {
	c := moveCluster()
	c.Platform.Serving = map[string]bool{"ens18": true}

	plan, err := planMoveAll(c, "ens19", "ens18")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Conflicts != 2 {
		t.Fatalf("conflicts = %d, want both tagged scopes refused: %+v", plan.Conflicts, plan.Rows)
	}
}

func TestPlanMoveAll_DisabledScopesMoveToo(t *testing.T) {
	c := moveCluster()
	b := c.Scopes["b"]
	b.DNSMasqDisabled = true
	c.Scopes["b"] = b

	plan, err := planMoveAll(c, "ens19", "ens20")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Rows) != 2 || !plan.Rows[1].Disabled {
		t.Fatalf("rows %+v, want the disabled scope moved and marked", plan.Rows)
	}
}

func TestMoveAllTemplate_OfferesStagingOnlyWithoutConflicts(t *testing.T) {
	clean, _ := planMoveAll(moveCluster(), "ens19", "ens20")
	c := moveCluster()
	c.Scopes["c"] = moveScope("ens20", 10, 3, "12")
	dirty, _ := planMoveAll(c, "ens19", "ens20")

	var a, b strings.Builder
	if err := moveAllTmpl.Execute(&a, moveAllPageData{Plan: &clean}); err != nil {
		t.Fatal(err)
	}
	if err := moveAllTmpl.Execute(&b, moveAllPageData{Plan: &dirty}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(a.String(), `action="/scopes/move-all/apply"`) {
		t.Error("a clean check must offer to stage the move")
	}
	if strings.Contains(b.String(), `action="/scopes/move-all/apply"`) {
		t.Error("a check with a conflict must not offer to stage anything")
	}
}
