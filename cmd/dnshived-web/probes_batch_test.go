// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestFetchProbeResults_OneCallPerHostThenPerScopeForOlderHosts(t *testing.T) {
	var batchCalls, singleCalls atomic.Int64
	modern := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/probe-results":
			batchCalls.Add(1)
			json.NewEncoder(w).Encode(map[string]any{"results": map[string]any{"a": map[string]any{"scope": "a", "probed_at": "2026-11-20T10:00:00Z"}}})
		case strings.HasPrefix(r.URL.Path, "/api/v1/probe/"):
			singleCalls.Add(1)
			json.NewEncoder(w).Encode(map[string]any{"scope": "x"})
		}
	}))
	defer modern.Close()
	older := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/probe/") {
			singleCalls.Add(1)
			json.NewEncoder(w).Encode(map[string]any{"scope": strings.TrimPrefix(r.URL.Path, "/api/v1/probe/"), "pending": true})
			return
		}
		http.NotFound(w, r)
	}))
	defer older.Close()
	hosts := []NodeConfig{
		{Name: "p1", Addr: strings.TrimPrefix(modern.URL, "http://")},
		{Name: "p2", Addr: strings.TrimPrefix(older.URL, "http://")},
	}
	got := fetchProbeResults([]string{"a", "b", "c"}, hosts)
	if len(got) != 6 {
		t.Fatalf("one result per scope and host: %d", len(got))
	}
	if batchCalls.Load() != 1 || singleCalls.Load() != 3 {
		t.Fatalf("a modern host takes one call, an older one a call per scope: batch %d, single %d", batchCalls.Load(), singleCalls.Load())
	}
	for _, r := range got {
		if r.worker == "p1" && r.scope == "b" && !r.pr.Pending {
			t.Error("a scope the batch does not hold is pending, as the single endpoint says")
		}
		if r.worker == "p1" && r.scope == "a" && r.pr.ProbedAt == "" {
			t.Error("the stored result must come through")
		}
	}
}
