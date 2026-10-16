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

func TestParseTokenSlots_BlankValueKeepsCurrentToken(t *testing.T) {
	current := []config.APIToken{{Name: "admin", Token: "tok-admin", Role: "admin"}, {Name: "monitor", Token: "tok-mon", Role: "readonly"}}
	form := map[string][]string{
		"__token_row_count__": {"4"},
		"token_name_0":        {"admin"}, "token_value_0": {""}, "token_role_0": {"admin"},
		"token_name_1": {""}, "token_value_1": {""},
		"token_name_2": {"new"}, "token_value_2": {"tok-new"}, "token_role_2": {"readonly"},
		"token_name_3": {"ghost"}, "token_value_3": {""},
	}
	got := parseTokenSlots(form, current)
	if len(got) != 2 || got[0].Name != "admin" || got[0].Token != "tok-admin" || got[1].Token != "tok-new" {
		t.Errorf("tokens = %+v; want admin kept, monitor removed (name cleared), new added, ghost ignored", got)
	}
}

func TestWithoutSecrets(t *testing.T) {
	c := withoutSecrets(config.Cluster{PSK: "psk", BackupPassword: "bp", APITokens: []config.APIToken{{Name: "a", Token: "t"}}})
	raw, _ := json.Marshal(c)
	for _, secret := range []string{`"psk":"psk"`, `"bp"`, `"t"`} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("withoutSecrets left %s in %s", secret, raw)
		}
	}
}

func fakeCore(t *testing.T, live config.Cluster) (addr string, pushed func() configPushPayload) {
	t.Helper()
	var mu sync.Mutex
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/candidate":
			w.Write([]byte(`{"exists":false}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/config":
			json.NewEncoder(w).Encode(live)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/candidate":
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			body = string(b)
			mu.Unlock()
			w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://"), func() configPushPayload {
		mu.Lock()
		defer mu.Unlock()
		var p configPushPayload
		if err := json.Unmarshal([]byte(body), &p); err != nil {
			t.Fatalf("unmarshal pushed payload: %v, body=%s", err, body)
		}
		return p
	}
}

func TestHandleConfigPost_BlankPSKKeepsCurrentAndMgmtOverridesSurvive(t *testing.T) {
	live := config.Cluster{PSK: "live-psk", Platform: &config.Platform{Mgmt: "ens18", Workers: []string{"ens19"},
		MgmtOverrides: map[string]string{"core-3": "eth0"}}}
	addr, pushed := fakeCore(t, live)
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: addr}}}
	form := url.Values{"psk": {""}, "platform_mgmt": {"ens18"}, "platform_workers": {"ens19"}, "log_level": {"info"}}
	req := httptest.NewRequest(http.MethodPost, "/config", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handleConfigPost(newConfigRef(cfg))(httptest.NewRecorder(), req)

	p := pushed()
	if p.PSK != "live-psk" {
		t.Errorf("PSK = %q, want the live PSK kept on a blank field", p.PSK)
	}
	if p.Platform == nil || p.Platform.MgmtOverrides["core-3"] != "eth0" {
		t.Errorf("MgmtOverrides lost on cluster save: %+v", p.Platform)
	}
}

func TestHandleConfigGet_NeverRendersPSK(t *testing.T) {
	addr, _ := fakeCore(t, config.Cluster{PSK: "super-secret-psk", BackupPassword: "bk-secret"})
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: addr}}}
	for _, path := range []string{"/config", "/backup"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if path == "/config" {
			handleConfigGet(newConfigRef(cfg))(rec, req)
		} else {
			handleBackup(newConfigRef(cfg))(rec, req)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d, the page must render for this test to mean anything", path, rec.Code)
		}
		body := rec.Body.String()
		if strings.Contains(body, "super-secret-psk") || strings.Contains(body, "bk-secret") {
			t.Errorf("%s leaks a secret to the browser", path)
		}
	}
}
