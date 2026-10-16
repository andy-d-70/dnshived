// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleDaemons_IncludesOwnNode(t *testing.T) {
	srv := selfFullServer(t, "core-3", nil, []daemonStatus{
		{Unit: "dnshived.service", LoadState: "loaded", ActiveState: "active", SubState: "running", UptimeSec: 3600},
	})
	cfg := &WebConfig{Nodes: []NodeConfig{unreachableSiblingNode(t, srv, "core-1")}}

	rec := httptest.NewRecorder()
	handleDaemons(newConfigRef(cfg))(rec, httptest.NewRequest("GET", "/daemons", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "no daemon data available") {
		t.Fatalf("page reports no daemon data at all — Daemons must fetch nodesIncludingSelf, not cfg.Nodes; body: %s", body)
	}
	if !strings.Contains(body, "dnshived.service") {
		t.Errorf("self node's own daemon row missing entirely; body: %s", body)
	}
	if !strings.Contains(body, "core-3") {
		t.Errorf("row does not name core-3 (self) as the reporting node; body: %s", body)
	}
}
