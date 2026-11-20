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
	"time"

	"dnshived/internal/config"
)

func TestFetchHostRows_OneCallPerCoreThenPerScopeForAnOlderCore(t *testing.T) {
	var batch, leases, neigh atomic.Int64
	h := func(modern bool) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/api/v1/hosts-view" && modern:
				batch.Add(1)
				out := map[string]any{}
				for _, n := range strings.Split(r.URL.Query().Get("scopes"), ",") {
					out[n] = map[string]any{"leases": []any{map[string]any{"mac": "aa:bb:cc:00:00:09", "ip": "10.0.0.120", "expiry": time.Now().Add(time.Hour)}}, "neighbors": []any{}, "neighbors_ok": true}
				}
				json.NewEncoder(w).Encode(map[string]any{"scopes": out})
			case strings.HasPrefix(r.URL.Path, "/api/v1/leases/"):
				leases.Add(1)
				json.NewEncoder(w).Encode(map[string]any{"leases": []any{}})
			case strings.HasPrefix(r.URL.Path, "/api/v1/neighbors/"):
				neigh.Add(1)
				json.NewEncoder(w).Encode(map[string]any{"neighbors": []any{}})
			default:
				http.NotFound(w, r)
			}
		})
	}
	modern := httptest.NewServer(h(true))
	defer modern.Close()
	older := httptest.NewServer(h(false))
	defer older.Close()

	sc := config.ScopeConfig{VIP: "10.0.0.254/24", DHCPRange: [2]string{"10.0.0.100", "10.0.0.200"}}
	cluster := config.Cluster{Scopes: map[string]config.ScopeConfig{"a": sc, "b": sc, "c": sc, "d": sc}}
	nodes := []NodeConfig{
		{Name: "core-1", Addr: strings.TrimPrefix(modern.URL, "http://")},
		{Name: "core-2", Addr: strings.TrimPrefix(older.URL, "http://")},
	}
	scopes := []scopeRow{{Name: "a", Worker: "core-1"}, {Name: "b", Worker: "core-1"}, {Name: "c", Worker: "core-2"}, {Name: "d", Worker: "core-2"}}
	rows := fetchHostRows(scopes, cluster, nodes, "", time.Now())
	if batch.Load() != 1 {
		t.Errorf("a modern core is asked once for all its scopes: %d", batch.Load())
	}
	if leases.Load() != 2 || neigh.Load() != 2 {
		t.Errorf("an older core is asked per scope: leases %d, neighbours %d", leases.Load(), neigh.Load())
	}
	dyn := 0
	for _, r := range rows {
		if r.IP == "10.0.0.120" {
			dyn++
		}
	}
	if dyn != 2 {
		t.Errorf("the batch leases of the two scopes come through: %d", dyn)
	}
}
