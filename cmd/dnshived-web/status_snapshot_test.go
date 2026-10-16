// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Andreas Dunkl

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newSelfAndSnapshotServer(t *testing.T, role, snapshotBody string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/config":
			fmt.Fprintf(w, `{"role":%q,"control_addr":%q}`, role, srv.Listener.Addr().String())
		case "/api/v1/cluster/snapshot":
			fmt.Fprint(w, snapshotBody)
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestFetchAllStatusViaSnapshot_Success(t *testing.T) {
	srv := newSelfAndSnapshotServer(t, "core-1", `{
		"self": {"status": {"role":"core-1","state":"STABLE","serving":["s1"]}},
		"peers": {
			"192.168.0.23:9443": {"status": {"role":"core-2","state":"STABLE","serving":["s2"]}}
		}
	}`)
	selfAddr := srv.Listener.Addr().String()

	cfg := &WebConfig{Nodes: []NodeConfig{
		{Name: "core-1", Addr: selfAddr, AdminToken: "tok"},
		{Name: "core-2", Addr: "192.168.0.23:9443", AdminToken: "tok"},
	}}

	rows, ok := fetchAllStatusViaSnapshot(cfg, cfg.Nodes)
	if !ok {
		t.Fatal("fetchAllStatusViaSnapshot ok = false, want true")
	}
	if len(rows) != 2 {
		t.Fatalf("len(rows) = %d, want 2", len(rows))
	}
	if rows[0].Status.Role != "core-1" || rows[0].FetchError != "" {
		t.Errorf("rows[0] = %+v, want self's own decoded status", rows[0])
	}
	if rows[1].Status.Role != "core-2" || rows[1].FetchError != "" {
		t.Errorf("rows[1] = %+v, want the bundled peer's decoded status, fetched with zero separate dial", rows[1])
	}
}

func TestFetchAllStatusViaSnapshot_PeerErrorEntry_SetsFetchError(t *testing.T) {
	srv := newSelfAndSnapshotServer(t, "core-1", `{
		"self": {"status": {"role":"core-1","state":"STABLE"}},
		"peers": {
			"192.168.0.24:9443": {"error": "dial tcp: connection refused"}
		}
	}`)
	selfAddr := srv.Listener.Addr().String()

	cfg := &WebConfig{Nodes: []NodeConfig{
		{Name: "core-1", Addr: selfAddr, AdminToken: "tok"},
		{Name: "core-3", Addr: "192.168.0.24:9443", AdminToken: "tok"},
	}}

	rows, ok := fetchAllStatusViaSnapshot(cfg, cfg.Nodes)
	if !ok {
		t.Fatal("fetchAllStatusViaSnapshot ok = false, want true")
	}
	if rows[1].FetchError == "" {
		t.Error("rows[1].FetchError is empty, want the server-reported error to carry through")
	}
}

func TestFetchAllStatusViaSnapshot_SelfUnresolvable_FallsBack(t *testing.T) {
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: "127.0.0.1:1", AdminToken: "tok"}}}
	if _, ok := fetchAllStatusViaSnapshot(cfg, cfg.Nodes); ok {
		t.Error("fetchAllStatusViaSnapshot ok = true, want false when self can't be resolved")
	}
}

func TestFetchAllStatusViaSnapshot_NodeNotCovered_FallsBack(t *testing.T) {
	srv := newSelfAndSnapshotServer(t, "core-1", `{
		"self": {"status": {"role":"core-1","state":"STABLE"}},
		"peers": {}
	}`)
	selfAddr := srv.Listener.Addr().String()

	cfg := &WebConfig{Nodes: []NodeConfig{
		{Name: "core-1", Addr: selfAddr, AdminToken: "tok"},
		{Name: "mystery", Addr: "10.0.0.99:9443", AdminToken: "tok"},
	}}

	if _, ok := fetchAllStatusViaSnapshot(cfg, cfg.Nodes); ok {
		t.Error("fetchAllStatusViaSnapshot ok = true, want false when a requested node isn't covered by the snapshot")
	}
}

func TestFetchAllStatus_FallsBackToLegacyWhenSnapshotEndpointMissing(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/config":
			fmt.Fprintf(w, `{"role":"core-1","control_addr":%q}`, srv.Listener.Addr().String())
		case "/api/v1/cluster/snapshot":
			w.WriteHeader(http.StatusNotFound)
		case "/api/v1/status":
			fmt.Fprint(w, `{"role":"core-1","state":"STABLE"}`)
		case "/api/v1/system":
			w.WriteHeader(http.StatusNotFound)
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	selfAddr := srv.Listener.Addr().String()

	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: selfAddr, TLS: true, AdminToken: "tok"}}}

	rows := fetchAllStatus(cfg, cfg.Nodes)
	if len(rows) != 1 || rows[0].Status.Role != "core-1" || rows[0].FetchError != "" {
		t.Errorf("rows = %+v, want a clean legacy-path result", rows)
	}
}

// TestFetchAllDaemonsViaSnapshot_Success confirms the Daemons page's own
// snapshot fast path decodes a bundled "daemons" field correctly.
func TestFetchAllDaemonsViaSnapshot_Success(t *testing.T) {
	srv := newSelfAndSnapshotServer(t, "core-1", `{
		"self": {
			"status": {"role":"core-1","state":"STABLE"},
			"daemons": {"node_id":"n1","daemons":[{"unit":"dnshived.service","active_state":"active"}]}
		},
		"peers": {}
	}`)
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: srv.Listener.Addr().String(), AdminToken: "tok"}}}

	results, ok := fetchAllDaemonsViaSnapshot(cfg, cfg.Nodes)
	if !ok {
		t.Fatal("fetchAllDaemonsViaSnapshot ok = false, want true")
	}
	if len(results) != 1 || results[0].Err != nil {
		t.Fatalf("results = %+v, want one clean decoded entry", results)
	}
	if len(results[0].Value.Daemons) != 1 || results[0].Value.Daemons[0].Unit != "dnshived.service" {
		t.Errorf("results[0].Value = %+v, want the bundled daemons field decoded", results[0].Value)
	}
}

func TestFetchAllDaemonsViaSnapshot_PerNodeIssueNeverFailsWholeBatch(t *testing.T) {
	srv := newSelfAndSnapshotServer(t, "core-1", `{
		"self": {
			"status": {"role":"core-1","state":"STABLE"},
			"daemons": {"node_id":"n1","daemons":[{"unit":"dnshived.service","active_state":"active"}]}
		},
		"peers": {
			"192.168.0.24:9443": {"error": "dial tcp: connection refused"}
		}
	}`)
	cfg := &WebConfig{Nodes: []NodeConfig{
		{Name: "core-1", Addr: srv.Listener.Addr().String(), AdminToken: "tok"},
		{Name: "core-3", Addr: "192.168.0.24:9443", AdminToken: "tok"},
	}}

	results, ok := fetchAllDaemonsViaSnapshot(cfg, cfg.Nodes)
	if !ok {
		t.Fatal("fetchAllDaemonsViaSnapshot ok = false, want true")
	}
	if results[0].Err != nil {
		t.Errorf("results[0].Err = %v, want nil for the healthy node", results[0].Err)
	}
	if results[1].Err == nil {
		t.Error("results[1].Err is nil, want the peer's own reported error to skip just that node")
	}
}

func TestFetchAllEvents_Success(t *testing.T) {
	srv := newSelfAndSnapshotServer(t, "core-1", `{
		"self": {
			"status": {"role":"core-1","state":"STABLE"},
			"events": [{"id":1,"level":"INFO","prefix":"AGENT","message":"hello","node_id":"n1"}]
		},
		"peers": {}
	}`)
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: srv.Listener.Addr().String(), AdminToken: "tok"}}}

	results, ok := fetchAllEvents(cfg, cfg.Nodes, logsFetchPerNode)
	if !ok {
		t.Fatal("fetchAllEvents ok = false, want true")
	}
	if len(results) != 1 || results[0].Err != nil || len(results[0].Value) != 1 || results[0].Value[0].Message != "hello" {
		t.Errorf("results = %+v, want one decoded event", results)
	}
}

func TestFetchAllEvents_WrongCountFallsBack(t *testing.T) {
	srv := newSelfAndSnapshotServer(t, "core-1", `{"self": {"status": {"role":"core-1"}}, "peers": {}}`)
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: srv.Listener.Addr().String(), AdminToken: "tok"}}}

	if _, ok := fetchAllEvents(cfg, cfg.Nodes, 10); ok {
		t.Error("fetchAllEvents ok = true, want false when the requested count differs from logsFetchPerNode")
	}
}

func TestFetchArbiterTokensViaSnapshot_Success(t *testing.T) {
	srv := newSelfAndSnapshotServer(t, "core-1", `{
		"self": {"status": {"role":"core-1"}},
		"peers": {},
		"tokens": {"test-42":{"owner":"n1","expires_at":"2026-01-01T00:00:00Z","expired":false}}
	}`)
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: srv.Listener.Addr().String(), AdminToken: "tok"}}}

	tokens, ok := fetchArbiterTokensViaSnapshot(cfg)
	if !ok {
		t.Fatal("fetchArbiterTokensViaSnapshot ok = false, want true")
	}
	if tok := tokens["test-42"]; tok.Owner != "n1" {
		t.Errorf("tokens[test-42].Owner = %q, want %q", tok.Owner, "n1")
	}
}

func TestFetchArbiterTokensViaSnapshot_EmptyFallsBack(t *testing.T) {
	srv := newSelfAndSnapshotServer(t, "core-1", `{"self": {"status": {"role":"core-1"}}, "peers": {}}`)
	cfg := &WebConfig{Nodes: []NodeConfig{{Name: "core-1", Addr: srv.Listener.Addr().String(), AdminToken: "tok"}}}

	if _, ok := fetchArbiterTokensViaSnapshot(cfg); ok {
		t.Error("fetchArbiterTokensViaSnapshot ok = true, want false when the snapshot carries no tokens field")
	}
}
