// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"dnshived/internal/config"
	"dnshived/internal/webauth"
)

func TestPushCandidateAndRenderResult_ReDerivesNodeIPPerNode(t *testing.T) {
	var pushedA, pushedB config.Cluster
	capture := func(dst *config.Cluster) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
				t.Errorf("decode pushed candidate: %v", err)
			}
			json.NewEncoder(w).Encode(map[string]any{"ok": true})
		}))
	}
	srvA := capture(&pushedA)
	defer srvA.Close()
	srvB := capture(&pushedB)
	defer srvB.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{
		nodeConfigFor(t, srvA),
		nodeConfigFor(t, srvB),
	}}
	cfg.Nodes[0].Name = "core-1"
	cfg.Nodes[1].Name = "core-2"

	payload := configPushPayload{
		Scopes: map[string]config.ScopeConfig{
			"office": {
				Parent: "ens19", VLANID: 42,
				VIP:    "192.168.10.254/24",
				NodeIP: "192.168.10.43/24", // placeholder — whichever node "current" came from
			},
		},
		ScopeDefaults: &config.ScopeDefaults{
			NodeIPSuffixes: map[string]string{"core-1": "23", "core-2": "22"},
		},
	}

	rec := httptest.NewRecorder()
	user := webauth.User{Name: "automation", Role: "admin"}
	pushCandidateAndRenderResult(rec, cfg, payload, user, "/", "back")

	if got := pushedA.Scopes["office"].NodeIP; got != "192.168.10.23/24" {
		t.Errorf("worker-a's own candidate has node_ip %q, want its own re-derived 192.168.10.23/24 (not the shared placeholder)", got)
	}
	if got := pushedB.Scopes["office"].NodeIP; got != "192.168.10.22/24" {
		t.Errorf("worker-b's own candidate has node_ip %q, want its own re-derived 192.168.10.22/24 (not the shared placeholder)", got)
	}
	if pushedA.Scopes["office"].NodeIP == pushedB.Scopes["office"].NodeIP {
		t.Errorf("both nodes received the identical node_ip %q — per-node re-derivation is not happening", pushedA.Scopes["office"].NodeIP)
	}
}
