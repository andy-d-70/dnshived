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

func TestHandleSecurityGet_RendersTokenNamesButNeverValues(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(config.Cluster{
			ClusterID: "lab01",
			APITokens: []config.APIToken{{Name: "admin", Token: "tok-abc", Role: "admin"}},
		})
	}))
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest(http.MethodGet, "/security", nil)
	rec := httptest.NewRecorder()

	handleSecurityGet(newConfigRef(cfg))(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "tok-abc") {
		t.Errorf("rendered page leaks the token value to the browser")
	}
	if !strings.Contains(body, `value="admin"`) {
		t.Errorf("rendered page is missing the existing token's name")
	}
}

func TestHandleSecurityPost_PreservesLiveClusterFieldsUnedited(t *testing.T) {
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
				Scopes:        map[string]config.ScopeConfig{"office": {VIP: "10.0.0.1/24"}},
				ScopeDefaults: &config.ScopeDefaults{GatewaySuffix: "1"},
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
	form := url.Values{
		"__token_row_count__": {"1"},
		"token_name_0":        {"new-token"},
		"token_value_0":       {"new-value"},
		"token_role_0":        {"readonly"},
	}
	req := httptest.NewRequest(http.MethodPost, "/security", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	handleSecurityPost(newConfigRef(cfg))(rec, req)

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
	if pushed.ScopeDefaults == nil || pushed.ScopeDefaults.GatewaySuffix != "1" {
		t.Errorf("ScopeDefaults not preserved: %+v", pushed.ScopeDefaults)
	}
	if len(pushed.APITokens) != 1 || pushed.APITokens[0].Name != "new-token" {
		t.Errorf("expected the actual edit (new-token) to land, got: %+v", pushed.APITokens)
	}
}
