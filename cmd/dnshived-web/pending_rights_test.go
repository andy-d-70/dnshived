// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"dnshived/internal/config"
	"dnshived/internal/webauth"
)

func TestOutsideScopeRights(t *testing.T) {
	live := config.Cluster{
		NodeID: "core-1-a", Role: "core-1", PSK: "k", LogLevel: "info",
		Scopes:        map[string]config.ScopeConfig{"office": {VLANID: 4}},
		ScopeDefaults: &config.ScopeDefaults{VIPSuffix: "254"},
	}
	scopeOnly := live
	scopeOnly.NodeID, scopeOnly.Role = "core-2-b", "core-2"
	scopeOnly.Scopes = map[string]config.ScopeConfig{"office": {VLANID: 4}, "lab": {VLANID: 20}}
	scopeOnly.ScopeDefaults = &config.ScopeDefaults{VIPSuffix: "1"}
	scopeOnly.DefaultDHCPOptions = []string{"option:ntp-server,10.0.0.1"}
	if got := outsideScopeRights(live, scopeOnly); got != nil {
		t.Errorf("scope-level changes (read from another core) refused: %v", got)
	}

	withPSK := scopeOnly
	withPSK.PSK = "other"
	if got := outsideScopeRights(live, withPSK); len(got) != 1 || got[0] != "psk" {
		t.Errorf("PSK change not named: %v", got)
	}
	hidden := live
	hidden.BindAddr = "0.0.0.0"
	hidden.LegacyDryRun = true
	if got := outsideScopeRights(live, hidden); got == nil {
		t.Error("a field the diff view does not list slipped through")
	}
}

func TestHandlePendingCommit_ScopeAdminRefusedForClusterChange(t *testing.T) {
	live := config.Cluster{LogLevel: "info"}
	candidate := config.Cluster{LogLevel: "debug"}
	srv := candidateTestServer(t, live, &candidate)
	defer srv.Close()
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}

	for _, path := range []string{"/pending/commit", "/pending/discard"} {
		req := withAuthedUser(httptest.NewRequest(http.MethodPost, path, nil), webauth.User{Name: "ops", Role: webauth.RoleScopeAdmin})
		rec := httptest.NewRecorder()
		if path == "/pending/commit" {
			handlePendingCommit(filepath.Join(t.TempDir(), "web.json"), newConfigRef(cfg))(rec, req)
		} else {
			handlePendingDiscard(newConfigRef(cfg))(rec, req)
		}
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "log_level") {
			t.Errorf("%s by scopeadmin: %d %s", path, rec.Code, rec.Body.String())
		}
	}
}
