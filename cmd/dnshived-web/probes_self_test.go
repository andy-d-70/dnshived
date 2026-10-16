// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleProbes_IncludesOwnNodesScope(t *testing.T) {
	srv := selfFullServer(t, "core-3", []string{"core3-test"}, nil)
	cfg := &WebConfig{
		Nodes:      []NodeConfig{unreachableSiblingNode(t, srv, "core-1")},
		ProbeHosts: []NodeConfig{{Name: "probe-1", Addr: "127.0.0.2:1"}},
	}

	rec := httptest.NewRecorder()
	handleProbes(newConfigRef(cfg))(rec, httptest.NewRequest("GET", "/probes", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "no scopes configured") {
		t.Fatalf("page reports no scopes at all — Probes must fetch nodesIncludingSelf, not cfg.Nodes; body: %s", body)
	}
	if !strings.Contains(body, "core3-test") {
		t.Errorf("self node's own scope missing entirely from the results grid; body: %s", body)
	}
}
