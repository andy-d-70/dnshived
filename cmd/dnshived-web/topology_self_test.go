// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleTopology_IncludesOwnNode(t *testing.T) {
	srv := selfFullServer(t, "core-3", []string{"core3-test"}, nil)
	cfg := &WebConfig{Nodes: []NodeConfig{unreachableSiblingNode(t, srv, "core-1")}}

	rec := httptest.NewRecorder()
	handleTopology(newConfigRef(cfg))(rec, httptest.NewRequest("GET", "/topology", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "core-3") {
		t.Errorf("self node's own role (core-3) missing entirely from the rendered tree; body: %s", body)
	}
	if !strings.Contains(body, "core3-test") {
		t.Errorf("self node's own scope (core3-test) missing entirely from the rendered tree; body: %s", body)
	}
}
