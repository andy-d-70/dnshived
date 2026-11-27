// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func auditNode(t *testing.T, name, body string, merged bool) NodeConfig {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if merged {
			w.Header().Set("X-Audit-Merged", "1")
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return NodeConfig{Name: name, Addr: strings.TrimPrefix(srv.URL, "http://")}
}

func TestHandleAudit_SharedLogOnceThenEachOlderNode(t *testing.T) {
	shared := `{"actor":"ann","summary":"shared"}` + "\n"
	cfg := &WebConfig{Nodes: []NodeConfig{
		auditNode(t, "core1", shared, true),
		auditNode(t, "core2", `{"actor":"bob","summary":"old node only"}`+"\n", false),
		auditNode(t, "core3", shared, true),
	}}
	rec := httptest.NewRecorder()
	handleAudit(newConfigRef(cfg))(rec, httptest.NewRequest(http.MethodGet, "/audit", nil))
	out := rec.Body.String()
	if strings.Count(out, `"shared"`) != 1 || strings.Count(out, "==== cluster") != 1 {
		t.Fatalf("the shared log appears once:\n%s", out)
	}
	if !strings.Contains(out, "==== core2") || !strings.Contains(out, "old node only") {
		t.Fatalf("an older node keeps its own section:\n%s", out)
	}
}
