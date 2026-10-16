// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// selfFullServer stands in for the core daemon co-located with this web
// instance.
func selfFullServer(t *testing.T, role string, scopes []string, units []daemonStatus) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/config":
			sc := map[string]any{}
			for _, s := range scopes {
				sc[s] = map[string]any{
					"parent": "ens19", "vlan_id": 18, "vip": "10.200.18.254/24",
					"gateway": "10.200.18.254", "dhcp_range": []string{"10.200.18.100", "10.200.18.200"},
				}
			}
			json.NewEncoder(w).Encode(map[string]any{
				"role": role, "control_addr": srv.Listener.Addr().String(), "scopes": sc,
			})
		case "/api/v1/status":
			json.NewEncoder(w).Encode(map[string]any{
				"role": role, "node_id": role + "-x", "state": "STABLE",
				"serving": scopes, "configured_scopes": scopes,
			})
		case "/api/v1/daemons":
			json.NewEncoder(w).Encode(map[string]any{"node_id": role + "-x", "daemons": units})
		case "/api/v1/candidate":
			json.NewEncoder(w).Encode(map[string]any{"exists": false})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// unreachableSiblingNode builds a cfg.Nodes entry sharing srv's own port
// but pointed at a different loopback address (127.0.0.2) that nothing
// listens on.
func unreachableSiblingNode(t *testing.T, srv *httptest.Server, name string) NodeConfig {
	t.Helper()
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split self server addr: %v", err)
	}
	return NodeConfig{Name: name, Addr: "127.0.0.2:" + port}
}
