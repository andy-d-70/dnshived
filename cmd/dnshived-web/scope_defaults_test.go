// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"dnshived/internal/config"
)

// TestHandleScopeDefaultsGet_RendersWithoutError is a template
// execute-time smoke test, mirroring this package's established pattern
// for every split-off page.
func TestHandleScopeDefaultsGet_RendersWithoutError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(config.Cluster{
			ClusterID:     "lab01",
			ScopeDefaults: &config.ScopeDefaults{VIPSuffix: "254", Upstream: []string{"1.1.1.1"}},
		})
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest(http.MethodGet, "/scopes/options", nil)
	rec := httptest.NewRecorder()

	handleScopeDefaultsGet(newConfigRef(cfg))(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "1.1.1.1") {
		t.Errorf("rendered page missing existing ScopeDefaults content, got:\n%s", body)
	}
}

func TestHandleScopeDefaultsPost_PreservesLiveClusterFieldsUnedited(t *testing.T) {
	var (
		mu         sync.Mutex
		pushedBody string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(config.Cluster{
				PSK: "secret-psk", LogLevel: "info",
				Scopes:    map[string]config.ScopeConfig{"office": {VIP: "10.0.0.1/24"}},
				APITokens: []config.APIToken{{Name: "admin", Token: "tok", Role: "admin"}},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/candidate":
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			pushedBody = string(body)
			mu.Unlock()
			w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	form := url.Values{"scope_defaults_vip_suffix": {"200"}}
	req := httptest.NewRequest(http.MethodPost, "/scopes/options", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	handleScopeDefaultsPost(newConfigRef(cfg))(rec, req)

	mu.Lock()
	body := pushedBody
	mu.Unlock()
	var pushed configPushPayload
	if err := json.Unmarshal([]byte(body), &pushed); err != nil {
		t.Fatalf("unmarshal pushed payload: %v, body=%s", err, body)
	}
	if pushed.PSK != "secret-psk" || pushed.LogLevel != "info" {
		t.Errorf("live cluster-wide fields not preserved: PSK=%q LogLevel=%q", pushed.PSK, pushed.LogLevel)
	}
	if pushed.Scopes["office"].VIP != "10.0.0.1/24" {
		t.Errorf("Scopes not preserved: %+v", pushed.Scopes)
	}
	if len(pushed.APITokens) != 1 || pushed.APITokens[0].Name != "admin" {
		t.Errorf("APITokens not preserved: %+v", pushed.APITokens)
	}
	if pushed.ScopeDefaults == nil || pushed.ScopeDefaults.VIPSuffix != "200" {
		t.Errorf("expected the actual edit (vip suffix 200) to land, got: %+v", pushed.ScopeDefaults)
	}
}
