// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"dnshived/internal/config"
)

func TestMoveToNodeScopes(t *testing.T) {
	scopes := map[string]config.ScopeConfig{
		"office": {PreferredWorker: "core-1", VLANID: 10, Extra: map[string]json.RawMessage{"future": json.RawMessage(`1`)}},
		"guest":  {PreferredWorker: "core-2", VLANID: 20, RebalanceApprovedAt: 7},
	}
	cores := []string{"core-1", "core-2", "core-3"}

	got, err := moveToNodeScopes(scopes, "office", "core-3", cores, 1234)
	if err != nil {
		t.Fatal(err)
	}
	if got["office"].PreferredWorker != "core-3" || got["office"].RebalanceApprovedAt != 1234 {
		t.Errorf("office = %+v, want preferred core-3 with the rebalance approved at 1234", got["office"])
	}
	if got["office"].VLANID != 10 || string(got["office"].Extra["future"]) != "1" {
		t.Errorf("the rest of the scope must stay, got %+v", got["office"])
	}
	if got["guest"].PreferredWorker != "core-2" || got["guest"].RebalanceApprovedAt != 7 {
		t.Errorf("another scope changed: %+v", got["guest"])
	}
	if scopes["office"].PreferredWorker != "core-1" || scopes["office"].RebalanceApprovedAt != 0 {
		t.Error("the input map must not be changed")
	}

	again, err := moveToNodeScopes(scopes, "guest", "core-2", cores, 99)
	if err != nil || again["guest"].RebalanceApprovedAt != 99 || again["guest"].PreferredWorker != "core-2" {
		t.Errorf("moving to the node it already prefers only approves the rebalance: %+v %v", again["guest"], err)
	}

	for name, tt := range map[string]struct {
		scope, node string
		cores       []string
		want        string
	}{
		"unknown scope":       {"nope", "core-1", cores, "not in the cluster configuration"},
		"not a core role":     {"office", "probe", cores, "not a core role"},
		"empty node":          {"office", "", cores, "not a core role"},
		"core not configured": {"office", "core-3", []string{"core-1", "core-2"}, "not a configured core"},
	} {
		if _, err := moveToNodeScopes(scopes, tt.scope, tt.node, tt.cores, 1); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: err = %v, want it to contain %q", name, err, tt.want)
		}
	}
}

func TestMoveTargets(t *testing.T) {
	rows := []statusRow{
		{Status: nodeStatus{Role: "core-2"}},
		{Status: nodeStatus{Role: "core-1"}},
		{Status: nodeStatus{Role: "core-3"}, FetchError: "timeout"},
		{Status: nodeStatus{Role: "probe"}},
	}
	cores := reachableCoreRoles(rows)
	if strings.Join(cores, ",") != "core-1,core-2" {
		t.Fatalf("reachable cores = %v, want core-1,core-2 (core-3 did not answer, the probe is no core)", cores)
	}
	if got := moveTargetsFor(cores, "core-1"); strings.Join(got, ",") != "core-2" {
		t.Errorf("targets from core-1 = %v", got)
	}
	if got := moveTargetsFor(cores, "—"); strings.Join(got, ",") != "core-1,core-2" {
		t.Errorf("an unserved scope can go to every reachable core, got %v", got)
	}
}

func TestScopesTmpl_MoveToNodeEntries(t *testing.T) {
	out := renderScopes(t, []scopeRow{
		{Name: "alpha", Display: "alpha", Worker: "core-1", MoveTargets: []string{"core-2", "core-3"}},
		{Name: "beta", Display: "beta", Worker: "core-2", MoveTargets: []string{"core-1"}},
		{Name: "gamma", Display: "gamma"},
	}, false)
	for _, want := range []string{
		`action="/scopes/alpha/move-to-node"`, `action="/scopes/beta/move-to-node"`,
		`<input type="hidden" name="node" value="core-2">`, `>Move to core-2</button>`, `>Move to core-3</button>`, `>Move to core-1</button>`,
		"Stage a move of scope alpha to core-2",
	} {
		if !strings.Contains(strings.ReplaceAll(out, "&#39;", "'"), want) {
			t.Errorf("menu lacks %q", want)
		}
	}
	if strings.Contains(out, `action="/scopes/gamma/move-to-node"`) {
		t.Error("a row without targets gets no move entries")
	}
	if strings.Count(out, `/move-to-node"`) != 3 {
		t.Errorf("want 3 move forms (2 + 1), got %d", strings.Count(out, `/move-to-node"`))
	}
}
