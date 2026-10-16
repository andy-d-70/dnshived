package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func selfServingServer(t *testing.T, role string, served []string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/config":
			scopes := map[string]any{}
			for _, s := range served {
				scopes[s] = map[string]any{
					"parent": "ens19", "vlan_id": 18, "vip": "10.200.18.254/24",
					"gateway": "10.200.18.254", "dhcp_range": []string{"10.200.18.100", "10.200.18.200"},
				}
			}
			json.NewEncoder(w).Encode(map[string]any{
				"role": role, "control_addr": srv.Listener.Addr().String(), "scopes": scopes,
			})
		case "/api/v1/status":
			json.NewEncoder(w).Encode(map[string]any{
				"role": role, "node_id": role + "-x", "state": "STABLE",
				"serving": served, "configured_scopes": served,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestHandleScopes_ScopeServedByOwnNodeIsNotShownAsNotServed(t *testing.T) {
	srv := selfServingServer(t, "core-3", []string{"core3-test"})
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split self server addr: %v", err)
	}
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: "127.0.0.2:" + port}}}

	rec := httptest.NewRecorder()
	handleScopes(newConfigRef(cfg))(rec, httptest.NewRequest("GET", "/scopes", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "core3-test") {
		t.Fatalf("scope row missing entirely; body: %s", body)
	}
	if strings.Contains(body, "not served") {
		t.Errorf("scope served by this instance's own node rendered as %q — Scopes must fetch nodesIncludingSelf, not cfg.Nodes", "not served")
	}
	if !strings.Contains(body, fmt.Sprintf(">%s<", "core-3")) && !strings.Contains(body, "core-3") {
		t.Errorf("row does not name core-3 as the serving node; body: %s", body)
	}
}
