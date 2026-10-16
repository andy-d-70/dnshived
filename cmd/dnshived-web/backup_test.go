// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"dnshived/internal/config"
)

func TestHandleBackup_RendersExportLinks(t *testing.T) {
	c := config.Cluster{ClusterID: "lab01"}
	srv := fakeConfigServer(t, c)
	defer srv.Close()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: strings.TrimPrefix(srv.URL, "http://")}}}
	req := httptest.NewRequest("GET", "/backup", nil)
	rec := httptest.NewRecorder()
	handleBackup(newConfigRef(cfg))(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"/config/export?mode=all", "/config/export?mode=cluster", "/config/export?mode=scopes", "lab01"} {
		if !strings.Contains(body, want) {
			t.Errorf("rendered page missing %q; body: %s", want, body)
		}
	}
}

func TestHandleBackup_IncludesSelfsOwnBackups(t *testing.T) {
	backups := []backupInfo{{Name: "backup-selftest.enc", Size: 42}}
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/config":
			fmt.Fprintf(w, `{"role":"core-3","control_addr":%q}`, srv.Listener.Addr().String())
		case "/api/v1/backups":
			json.NewEncoder(w).Encode(backups)
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split self server addr: %v", err)
	}
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: "127.0.0.2:" + port}}}

	req := httptest.NewRequest("GET", "/backup", nil)
	rec := httptest.NewRecorder()
	handleBackup(newConfigRef(cfg))(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "backup-selftest.enc") {
		t.Errorf("rendered page missing self's own backup (backup-selftest.enc) — cfg.Nodes alone can never see it, nodesIncludingSelf must be used")
	}
}
